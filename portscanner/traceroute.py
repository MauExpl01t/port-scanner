"""Traceroute (--traceroute): usa el programa del sistema (tracert / traceroute) y lee su resultado."""
from __future__ import annotations

import re
import shutil
import sys

from .discovery import _run

_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_RTT_RE = re.compile(r"(<?\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})")


def parse_traceroute(output: str) -> list[dict]:
    """Convierte la salida de tracert/traceroute en [{'hop': 1, 'address': '...', 'rtt_ms': 1.2}, ...]."""
    hops: list[dict] = []
    for line in output.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        hop, rest = int(m.group(1)), m.group(2)
        if hop > 64:
            continue
        ip = _IP_RE.search(rest)
        rtts = []
        for r in _RTT_RE.findall(rest):
            try:
                value = float(r.lstrip("<").replace(",", "."))
                rtts.append(value)
            except ValueError:
                pass
        hops.append({"hop": hop, "address": ip.group(1) if ip else "*",
                     "rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None})
    return hops


async def traceroute(host: str, max_hops: int = 20, timeout: float = 1.0) -> tuple[list[dict], str]:
    """Devuelve (saltos, mensaje_de_error). El mensaje está vacío si todo salió bien."""
    ms = str(max(200, int(timeout * 1000)))
    if sys.platform == "win32":
        if not shutil.which("tracert"):
            return [], "no se encontró el programa 'tracert'"
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", ms] + (["-6"] if ":" in host else []) + [host]
    else:
        prog = "traceroute6" if ":" in host and shutil.which("traceroute6") else "traceroute"
        if not shutil.which(prog):
            return [], f"no se encontró el programa '{prog}' (instálalo con tu gestor de paquetes)"
        cmd = [prog, "-n", "-m", str(max_hops), "-w", str(max(1, round(timeout))), "-q", "1", host]
    out = await _run(cmd, max_hops * (timeout * 3 + 1) + 10)
    hops = parse_traceroute(out)
    if not hops:
        return [], "no se pudo leer el resultado del traceroute"
    return hops, ""
