"""Descubrimiento de equipos: ¿está encendido este host?

Se combinan tres pistas (no hacen falta permisos de administrador):
  1. ping del sistema (eco ICMP)      -> además entrega el TTL, útil para adivinar el sistema operativo
  2. intento de conexión TCP a puertos comunes: si el puerto está abierto O responde "rechazado",
     el equipo está vivo (solo un equipo apagado o con firewall que descarta todo no contesta)
  3. tabla ARP del sistema: después de probar, el sistema operativo recuerda la dirección física (MAC)
     de los equipos de tu red local que respondieron
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable

from .tcp import try_connect

DEFAULT_TCP_PING_PORTS = [80, 443, 22, 445, 3389, 8080, 21, 25, 53, 135, 139, 23, 5900]

_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_TTL_RE = re.compile(r"\bttl[=:]\s*(\d+)", re.IGNORECASE)
_TIME_RE = re.compile(r"(?:time|tiempo|temps|zeit|tempo)\s*([=<])\s*([\d.,]+)\s*m", re.IGNORECASE)
_MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_REFUSED_CODES = {111, 61, 10061, 1225, 54, 10054, 104}


@dataclass
class Discovery:
    up: bool = False
    reason: str = "no-response"
    latency_ms: float | None = None
    ttl: int | None = None
    mac: str = ""


def _ping_command(host: str, timeout: float) -> list[str]:
    v6 = ":" in host
    ms = max(200, int(timeout * 1000))
    if sys.platform == "win32":
        return ["ping", "-6" if v6 else "-4", "-n", "1", "-w", str(ms), host]
    if sys.platform == "darwin":
        return ["ping6" if v6 else "ping", "-c", "1", "-W", str(ms), host] if not v6 else ["ping6", "-c", "1", host]
    return ["ping", "-6" if v6 else "-4", "-c", "1", "-W", str(max(1, round(timeout))), host]


async def _run(cmd: list[str], timeout: float) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL, creationflags=_CREATE_NO_WINDOW)
    except (OSError, NotImplementedError):
        return ""
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return ""
    return out.decode("utf-8", "replace") if sys.platform != "win32" else out.decode("cp850", "replace")


def parse_ping(output: str, host: str) -> tuple[int, float | None] | None:
    """Devuelve (ttl, latencia_ms) si la salida de ping muestra una respuesta REAL del host, o None."""
    for line in output.splitlines():
        m = _TTL_RE.search(line)
        if not m:
            continue
        if ":" not in host and host not in line:
            continue      # Windows muestra "Respuesta desde <router>: host inaccesible": no cuenta
        latency = None
        t = _TIME_RE.search(line)
        if t:
            try:
                latency = float(t.group(2).replace(",", "."))
                if t.group(1) == "<":
                    latency = max(0.1, latency / 2)
            except ValueError:
                latency = None
        return int(m.group(1)), latency
    return None


async def icmp_ping(host: str, timeout: float) -> Discovery:
    started = time.monotonic()
    out = await _run(_ping_command(host, timeout), timeout + 3)
    parsed = parse_ping(out, host)
    if not parsed:
        return Discovery()
    ttl, latency = parsed
    return Discovery(True, "echo-reply", latency if latency is not None else (time.monotonic() - started) * 1000, ttl)


async def tcp_ping(host: str, ports: list[int], timeout: float) -> Discovery:
    """Vivo si algún puerto acepta la conexión o la rechaza activamente."""
    best = Discovery()

    async def one(port: int) -> None:
        nonlocal best
        started = time.monotonic()
        try:
            await try_connect(host, port, timeout)
            reason = "syn-ack"
        except (ConnectionRefusedError, ConnectionResetError):
            reason = "conn-refused"
        except OSError as exc:
            code = getattr(exc, "winerror", None) or exc.errno
            if code not in _REFUSED_CODES:
                return
            reason = "conn-refused"
        except (asyncio.TimeoutError, TimeoutError):
            return
        if not best.up or (reason == "syn-ack" and best.reason != "syn-ack"):
            best = Discovery(True, reason, (time.monotonic() - started) * 1000)

    await asyncio.gather(*(one(p) for p in ports))
    return best


def _normalize_mac(raw: str) -> str:
    parts = re.split(r"[:-]", raw)
    return ":".join(p.zfill(2).lower() for p in parts)


def parse_arp(output: str) -> dict[str, str]:
    table: dict[str, str] = {}
    for line in output.splitlines():
        ip_m, mac_m = _IP_RE.search(line), _MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        try:
            ip = ipaddress.ip_address(ip_m.group(1))
        except ValueError:
            continue
        mac = _normalize_mac(mac_m.group(1))
        if ip.is_multicast or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac.startswith("01:00:5e"):
            continue
        table[str(ip)] = mac
    return table


async def read_arp_table() -> dict[str, str]:
    return parse_arp(await _run(["arp", "-a"], 6))


def _is_local_candidate(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.version == 4 and (ip.is_private or ip.is_link_local) and not ip.is_loopback


async def discover_hosts(addresses: list[str], *, icmp: bool = True, tcp_ports: list[int] | None = None,
                         timeout: float = 1.5, parallel: int = 128,
                         progress: Callable[[int, int], None] | None = None) -> dict[str, Discovery]:
    """Descubre cuáles de las direcciones están activas."""
    tcp_ports = DEFAULT_TCP_PING_PORTS if tcp_ports is None else tcp_ports
    sem = asyncio.Semaphore(parallel)
    ping_sem = asyncio.Semaphore(24)       # no lanzar cientos de procesos "ping" a la vez
    results: dict[str, Discovery] = {}
    done = 0

    async def one(address: str) -> None:
        nonlocal done
        async with sem:
            jobs = []
            if icmp:
                async def guarded() -> Discovery:
                    async with ping_sem:
                        return await icmp_ping(address, timeout)
                jobs.append(guarded())
            if tcp_ports:
                jobs.append(tcp_ping(address, tcp_ports, timeout))
            found = await asyncio.gather(*jobs) if jobs else []
        chosen = Discovery()
        for d in found:
            if d.up:
                if not chosen.up:
                    chosen = d
                else:       # combina: el ping aporta TTL, TCP aporta razón
                    chosen.ttl = chosen.ttl or d.ttl
                    chosen.latency_ms = chosen.latency_ms if chosen.latency_ms is not None else d.latency_ms
        results[address] = chosen
        done += 1
        if progress:
            progress(done, len(addresses))

    await asyncio.gather(*(one(a) for a in addresses))

    if any(_is_local_candidate(a) for a in addresses):
        table = await read_arp_table()
        for address, d in results.items():
            mac = table.get(address)
            if mac:
                d.mac = mac
                if not d.up:
                    d.up, d.reason = True, "arp-cache"
    return results
