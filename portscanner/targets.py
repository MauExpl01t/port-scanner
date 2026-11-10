"""Lectura de objetivos: IP, nombre, red CIDR, rangos por octeto y archivo de lista."""
from __future__ import annotations

import ipaddress
import itertools
import re
from dataclasses import dataclass

from . import dnsutil

MAX_TARGETS_HARD = 65536     # más que esto se rechaza siempre
LARGE_SCAN = 256             # más que esto exige --i-accept-large-scan

_OCTET = re.compile(r"^\d{1,3}(-\d{1,3})?(,\d{1,3}(-\d{1,3})?)*$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    address: str
    name: str = ""


def _check_address(ip: ipaddress._BaseAddress, original: str) -> None:
    if ip.is_unspecified:
        raise TargetError(f"{original}: la dirección 'cualquiera' (0.0.0.0 / ::) no es un equipo que se pueda escanear")
    if ip.is_multicast:
        raise TargetError(f"{original}: es una dirección multicast, no un equipo")
    if isinstance(ip, ipaddress.IPv4Address) and int(ip) == 0xFFFFFFFF:
        raise TargetError(f"{original}: es la dirección de broadcast")


def _octet_values(part: str) -> list[int]:
    values: list[int] = []
    for piece in part.split(","):
        if "-" in piece:
            a, b = (int(x) for x in piece.split("-"))
            if a > b:
                raise TargetError(f"rango de octeto al revés: {piece!r}")
            values.extend(range(a, b + 1))
        else:
            values.append(int(piece))
    if any(v > 255 for v in values):
        raise TargetError("cada número de una IP va de 0 a 255")
    return values


def _is_octet_range(spec: str) -> bool:
    parts = spec.split(".")
    return len(parts) == 4 and all(_OCTET.match(p) for p in parts) and any(("-" in p or "," in p) for p in parts)


def _count(spec: str) -> int | None:
    """Cantidad de equipos que describe el objetivo (None si es un nombre, que cuenta como 1)."""
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            raise TargetError(f"red inválida: {spec!r}") from None
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 31:
            return net.num_addresses - 2
        return net.num_addresses
    if _is_octet_range(spec):
        total = 1
        for p in spec.split("."):
            total *= len(_octet_values(p))
        return total
    return None


def _expand_one(spec: str, resolver, dns_server) -> list[Target]:
    spec = spec.strip()
    if not spec:
        raise TargetError("hay un objetivo vacío")
    try:
        ip = ipaddress.ip_address(spec)
        _check_address(ip, spec)
        return [Target(str(ip))]
    except ValueError:
        pass
    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        hosts = net.hosts() if net.prefixlen < (31 if net.version == 4 else 127) else iter(net)
        out = []
        for h in hosts:
            _check_address(h, spec)
            out.append(Target(str(h)))
        return out
    if _is_octet_range(spec):
        lists = [_octet_values(p) for p in spec.split(".")]
        return [Target(".".join(map(str, combo))) for combo in itertools.product(*lists)]
    if not _HOSTNAME.match(spec):
        raise TargetError(f"no entiendo el objetivo {spec!r} (usa IP, nombre, red 10.0.0.0/24 o rango 10.0.0.1-50)")
    try:
        ips = resolver(spec, dns_server)
    except dnsutil.DnsError as exc:
        raise TargetError(str(exc)) from None
    ip = ipaddress.ip_address(ips[0])
    _check_address(ip, spec)
    return [Target(str(ip), spec)]


def expand_targets(specs: list[str], exclude: list[str] | None = None, *, dns_server: str | None = None,
                   large_ok: bool = False, resolver=dnsutil.resolve) -> list[Target]:
    """Convierte los objetivos del usuario en una lista de equipos, sin repetidos y sin los excluidos."""
    if not specs:
        raise TargetError("falta al menos un objetivo")
    total = 0
    for spec in specs:
        n = _count(spec.strip())
        total += 1 if n is None else max(n, 0)
    if total > MAX_TARGETS_HARD:
        raise TargetError(f"son {total} equipos: el máximo permitido es {MAX_TARGETS_HARD}. Divide el escaneo en partes.")
    if total > LARGE_SCAN and not large_ok:
        raise TargetError(
            f"son {total} equipos (más de {LARGE_SCAN}). Si de verdad tienes autorización para escanear esa "
            "cantidad, agrega --i-accept-large-scan.")

    excluded: set[str] = set()
    for spec in exclude or []:
        for t in _expand_one(spec, resolver, dns_server):
            excluded.add(t.address)

    seen: set[str] = set()
    out: list[Target] = []
    for spec in specs:
        for t in _expand_one(spec, resolver, dns_server):
            if t.address in excluded or t.address in seen:
                continue
            seen.add(t.address)
            out.append(t)
    if not out:
        raise TargetError("después de aplicar las exclusiones no quedó ningún equipo")
    return out


def read_target_file(path: str) -> list[str]:
    """Lee un archivo con un objetivo por línea (admite comentarios con # y líneas vacías)."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise TargetError(f"no pude leer {path!r}: {exc.strerror or exc}") from None
    out: list[str] = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.extend(line.split())
    if not out:
        raise TargetError(f"el archivo {path!r} no tiene objetivos")
    return out
