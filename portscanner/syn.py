"""Escaneo SYN (-sS), OPCIONAL y EXPERIMENTAL.

Envía solo el primer paquete (SYN) sin completar la conexión. Necesita:
  - la librería `scapy`  (pip install scapy)
  - en Windows: Npcap instalado (https://npcap.com) y una consola de administrador
  - en Linux/macOS: ejecutar como root
Si algo falta, el escáner avisa y usa el modo connect normal (-sT). No está probado en este equipo.
"""
from __future__ import annotations

import asyncio
import os
import sys

from .models import CLOSED, FILTERED, OPEN, PortResult
from .ports import service_name


def is_admin() -> bool:
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def availability() -> tuple[bool, str]:
    """(disponible, motivo_si_no)."""
    try:
        import scapy.all  # noqa: F401
    except Exception:
        return False, "falta la librería scapy (pip install scapy)"
    if not is_admin():
        return False, "hacen falta permisos de administrador (Windows) o root (Linux/macOS)"
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list  # noqa: F401
            import scapy.config
            if not getattr(scapy.config.conf, "use_pcap", False):
                return False, "no se detectó Npcap (https://npcap.com)"
        except Exception:
            return False, "no se detectó Npcap (https://npcap.com)"
    return True, ""


def _syn_scan_blocking(host: str, ports: list[int], timeout: float) -> list[PortResult]:
    from scapy.all import IP, IPv6, TCP, conf, sr  # type: ignore
    conf.verb = 0
    layer = IPv6(dst=host) if ":" in host else IP(dst=host)
    answered, unanswered = sr(layer / TCP(dport=ports, flags="S"), timeout=timeout, verbose=0)
    results: dict[int, PortResult] = {}
    for sent, received in answered:
        port = sent[TCP].dport
        tcp = received.getlayer(TCP)
        if tcp is not None and tcp.flags & 0x12 == 0x12:
            state, reason = OPEN, "syn-ack"
        elif tcp is not None and tcp.flags & 0x04:
            state, reason = CLOSED, "reset"
        else:
            state, reason = FILTERED, "icmp-unreachable"
        results[port] = PortResult(port, "tcp", state, reason, service_name(port, "tcp"))
    for sent in unanswered:
        port = sent[TCP].dport
        results.setdefault(port, PortResult(port, "tcp", FILTERED, "no-response", service_name(port, "tcp")))
    return [results[p] for p in sorted(results)]


async def syn_scan(host: str, ports: list[int], timeout: float = 2.0, batch: int = 2000) -> list[PortResult]:
    loop = asyncio.get_running_loop()
    out: list[PortResult] = []
    for i in range(0, len(ports), batch):
        out.extend(await loop.run_in_executor(None, _syn_scan_blocking, host, ports[i:i + batch], timeout))
    return out
