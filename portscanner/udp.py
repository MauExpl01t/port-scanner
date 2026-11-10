"""Escaneo UDP.

UDP no tiene "conexión", así que el resultado se deduce así:
  - El puerto responde con datos           -> abierto
  - El equipo avisa "puerto inalcanzable"  -> cerrado  (mensaje ICMP del sistema operativo)
  - No pasa nada                           -> abierto|filtrado (no se puede saber cuál de los dos)
Para que los servicios respondan se envía una sonda propia de cada protocolo (DNS, NTP, SNMP...).
"""
from __future__ import annotations

import asyncio
import errno
import re
import struct
import time
from collections import deque

from . import dnsutil
from .models import CLOSED, FILTERED, OPEN, OPEN_FILTERED, PortResult
from .ports import service_name
from .tcp import _LOCAL_LIMIT, _REFUSED, _RESET, _UNREACHABLE, ProgressFn, _os_code
from .timing import Timing


def _tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    raw = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def snmp_get_sysdescr(community: bytes = b"public", request_id: int = 0x70737031) -> bytes:
    oid = _tlv(0x06, bytes([0x2B, 6, 1, 2, 1, 1, 1, 0]))          # 1.3.6.1.2.1.1.1.0 (sysDescr)
    varbind = _tlv(0x30, oid + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _tlv(0x02, request_id.to_bytes(4, "big")) + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00")
               + _tlv(0x30, varbind))
    return _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, community) + pdu)


def _nbns_status() -> bytes:
    name = b"CK" + b"A" * 30
    return b"\x80\xf0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + name + b"\x00\x00\x21\x00\x01"


def _sip_options() -> bytes:
    return (b"OPTIONS sip:nm@localhost SIP/2.0\r\nVia: SIP/2.0/UDP localhost:5060;branch=z9hG4bKportscan\r\n"
            b"From: <sip:scan@localhost>;tag=ps\r\nTo: <sip:nm@localhost>\r\nCall-ID: portscanner@localhost\r\n"
            b"CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")


PROBES: dict[int, bytes] = {
    53: dnsutil.build_query("example.com", 1, 0x5053),
    69: b"\x00\x01portscanner-test\x00octet\x00",
    111: struct.pack("!IIIIIIIIII", 0x70737031, 0, 2, 100000, 2, 0, 0, 0, 0, 0),
    123: b"\x1b" + b"\x00" * 47,
    137: _nbns_status(),
    161: snmp_get_sysdescr(),
    623: b"\x06\x00\xff\x06\x00\x00\x11\xbe\x80\x00\x00\x00",
    1434: b"\x02",
    1900: (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\n'
           b"ST: ssdp:all\r\n\r\n"),
    5060: _sip_options(),
    5353: dnsutil.build_query("_services._dns-sd._udp.local", 12, 0x5353, recursion=False),
    11211: b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
}
GENERIC_PROBE = b"\x00"


def describe_response(port: int, data: bytes) -> tuple[str, str, str]:
    """Devuelve (servicio, producto, texto_extra) a partir de lo que respondió el puerto UDP."""
    if port == 161 and data[:1] == b"\x30":
        m = re.search(rb"\x04([\x20-\x7e]{3,200})", data[10:])
        return "snmp", "", (m.group(1).decode("ascii", "replace") if m else "")
    if port == 123 and len(data) >= 48:
        return "ntp", "", f"NTP v{(data[0] >> 3) & 7}, stratum {data[1]}"
    if port == 137 and len(data) > 57:
        names = []
        for i in range(data[56]):
            raw = data[57 + i * 18:57 + i * 18 + 15]
            if len(raw) == 15:
                n = raw.decode("ascii", "replace").strip()
                if n and n not in names:
                    names.append(n)
        return "netbios-ns", "", ", ".join(names[:4])
    if port == 1900:
        m = re.search(rb"(?im)^server:\s*(.+)$", data)
        return "upnp", "", (m.group(1).decode("ascii", "replace").strip() if m else "")
    if port == 11211:
        return "memcached", "", "responde a 'stats' sin autenticación"
    if port == 53:
        return "domain", "", ""
    if port == 5060 and data.startswith(b"SIP/2.0"):
        m = re.search(rb"(?im)^server:\s*(.+)$", data)
        return "sip", "", (m.group(1).decode("ascii", "replace").strip() if m else "")
    if port == 1434 and data[:1] == b"\x05":
        return "ms-sql-m", "Microsoft SQL Server Browser", data[3:120].decode("ascii", "replace").replace("\x00", " ")
    return service_name(port, "udp"), "", ""


class _Probe(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future, payload: bytes):
        self.future = future
        self.payload = payload
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        try:
            transport.sendto(self.payload)
        except OSError as exc:
            self._finish(("error", exc))

    def datagram_received(self, data, addr):
        self._finish(("data", data))

    def error_received(self, exc):
        self._finish(("error", exc))

    def connection_lost(self, exc):
        self._finish(("error", exc or ConnectionError("conexión cerrada")))

    def _finish(self, value):
        if not self.future.done():
            self.future.set_result(value)


async def probe_udp_port(host: str, port: int, timing: Timing, *, payload: bytes | None = None) -> PortResult:
    result = PortResult(port=port, protocol="udp", state=OPEN_FILTERED, reason="no-response",
                        service=service_name(port, "udp"))
    payload = payload if payload is not None else PROBES.get(port, GENERIC_PROBE)
    loop = asyncio.get_running_loop()
    attempts = max(timing.retries, 1) + 1       # UDP pierde paquetes: al menos un reintento
    local_retries = 0
    attempt = 0
    while attempt < attempts:
        attempt += 1
        future: asyncio.Future = loop.create_future()
        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(lambda: _Probe(future, payload),
                                                               remote_addr=(host, port))
            kind, value = await asyncio.wait_for(future, timing.timeout)
        except (asyncio.TimeoutError, TimeoutError):
            if transport is not None:
                transport.close()
            continue
        except OSError as exc:
            kind, value = "error", exc
        finally:
            if transport is not None:
                transport.close()
        if kind == "data":
            result.state, result.reason = OPEN, "udp-response"
            svc, product, extra = describe_response(port, value)
            result.service, result.product, result.extrainfo = svc, product, extra
            result.confirmed = True
            result.banner = re.sub(r"[^\x20-\x7e]", ".", value[:160].decode("latin-1"))
            return result
        code = _os_code(value) if isinstance(value, OSError) else None
        if isinstance(value, (ConnectionRefusedError, ConnectionResetError)) or code in _REFUSED | _RESET:
            result.state, result.reason = CLOSED, "port-unreach"
            return result
        if code in _UNREACHABLE:
            result.state, result.reason = FILTERED, "host-unreachable"
            return result
        if code in _LOCAL_LIMIT or code == errno.EAGAIN:
            local_retries += 1
            if local_retries <= 8:
                attempt -= 1
                await asyncio.sleep(0.15 * local_retries)
                continue
        result.state, result.reason = FILTERED, f"error-{code}"
        return result
    return result


async def scan_udp_ports(host: str, ports: list[int], timing: Timing, *, concurrency: int | None = None,
                         progress: ProgressFn | None = None,
                         sink: dict[int, PortResult] | None = None) -> list[PortResult]:
    pending = deque(ports)
    total = len(ports)
    results: dict[int, PortResult] = sink if sink is not None else {}
    done = 0
    last = 0.0
    workers_n = max(1, min(concurrency or min(timing.concurrency, 300), total or 1))

    async def worker() -> None:
        nonlocal done, last
        while pending:
            port = pending.popleft()
            results[port] = await probe_udp_port(host, port, timing)
            done += 1
            if progress and (time.monotonic() - last >= 0.5 or done == total):
                last = time.monotonic()
                progress(done, total)
            if timing.delay and pending:
                await asyncio.sleep(timing.delay)

    tasks = [asyncio.create_task(worker()) for _ in range(workers_n)]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return [results[p] for p in sorted(results)]


async def udp_request(host: str, port: int, payload: bytes, timeout: float = 2.0, retries: int = 1) -> bytes | None:
    """Envía un datagrama UDP y devuelve la respuesta (o None si no hubo)."""
    loop = asyncio.get_running_loop()
    for _ in range(retries + 1):
        future: asyncio.Future = loop.create_future()
        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(lambda: _Probe(future, payload),
                                                               remote_addr=(host, port))
            kind, value = await asyncio.wait_for(future, timeout)
        except (asyncio.TimeoutError, TimeoutError):
            continue
        except OSError:
            return None
        finally:
            if transport is not None:
                transport.close()
        return value if kind == "data" else None
    return None
