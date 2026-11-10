"""Cliente DNS mínimo (solo librería estándar) para usar un servidor DNS propio (--dns-server)
y para armar la sonda DNS del escaneo UDP."""
from __future__ import annotations

import ipaddress
import random
import socket
import struct

QTYPES = {"A": 1, "NS": 2, "PTR": 12, "TXT": 16, "AAAA": 28}


class DnsError(Exception):
    pass


def build_query(name: str, qtype: int = 1, qid: int | None = None, recursion: bool = True) -> bytes:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    flags = 0x0100 if recursion else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    question = b""
    name = name.rstrip(".")
    if name:
        for label in name.split("."):
            raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
            if not raw or len(raw) > 63:
                raise DnsError(f"etiqueta DNS inválida en {name!r}")
            question += bytes([len(raw)]) + raw
    question += b"\x00" + struct.pack("!HH", qtype, 1)
    return header + question


def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    hops = 0
    while True:
        if pos >= len(data):
            raise DnsError("respuesta DNS cortada")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsError("puntero DNS cortado")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            pos = pointer
            hops += 1
            if hops > 20:
                raise DnsError("bucle de punteros DNS")
            continue
        pos += 1
        labels.append(data[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def parse_response(data: bytes, expect_id: int | None = None) -> tuple[int, list[tuple[int, object]]]:
    """Devuelve (rcode, [(tipo, valor)]) con A/AAAA como texto de IP y PTR/NS como nombre."""
    if len(data) < 12:
        raise DnsError("respuesta DNS demasiado corta")
    qid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if expect_id is not None and qid != expect_id:
        raise DnsError("la respuesta DNS no corresponde a la consulta")
    rcode = flags & 0x000F
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(data, pos)
        pos += 4
    answers: list[tuple[int, object]] = []
    for _ in range(an):
        _, pos = _read_name(data, pos)
        if pos + 10 > len(data):
            raise DnsError("respuesta DNS cortada")
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        if len(rdata) < rdlen:
            raise DnsError("respuesta DNS cortada")
        if rtype == 1 and rdlen == 4:
            answers.append((rtype, socket.inet_ntoa(rdata)))
        elif rtype == 28 and rdlen == 16:
            answers.append((rtype, socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype in (2, 5, 12):
            answers.append((rtype, _read_name(data, pos)[0]))
        pos += rdlen
    return rcode, answers


def query(name: str, qtype: str, server: str, timeout: float = 3.0, port: int = 53) -> list[tuple[int, object]]:
    qid = random.randint(0, 0xFFFF)
    packet = build_query(name, QTYPES[qtype], qid)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, port))
            data, _ = sock.recvfrom(4096)
        except OSError as exc:
            raise DnsError(f"el servidor DNS {server} no respondió: {exc}") from exc
    _rcode, answers = parse_response(data, qid)
    return answers


def validate_server(server: str) -> str:
    try:
        return str(ipaddress.ip_address(server.strip()))
    except ValueError:
        raise DnsError(f"--dns-server debe ser una dirección IP (recibí {server!r})") from None


def resolve(name: str, server: str | None = None, timeout: float = 3.0) -> list[str]:
    """Resuelve un nombre a IPs (IPv4 primero). Con server=None usa el DNS del sistema."""
    if server is None:
        try:
            infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise DnsError(f"no pude resolver {name!r}: {exc.strerror or exc}") from exc
        found = [i[4][0] for i in infos]
    else:
        found = []
        for qtype in ("A", "AAAA"):
            try:
                found += [str(v) for t, v in query(name, qtype, server, timeout) if t in (1, 28)]
            except DnsError:
                if qtype == "A":
                    raise
    ordered: list[str] = []
    for ip in sorted(set(found), key=lambda v: (":" in v, found.index(v))):
        ordered.append(ip)
    if not ordered:
        raise DnsError(f"{name!r} no tiene dirección IP")
    return ordered


def reverse(ip: str, server: str | None = None, timeout: float = 2.0) -> str:
    """Nombre asociado a una IP (búsqueda inversa). Devuelve '' si no tiene."""
    try:
        if server is None:
            return socket.gethostbyaddr(ip)[0]
        ptr = ipaddress.ip_address(ip).reverse_pointer
        for t, v in query(ptr, "PTR", server, timeout):
            if t == 12:
                return str(v)
    except (OSError, DnsError, ValueError):
        pass
    return ""
