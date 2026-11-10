"""Adivina el sistema operativo (-O) a partir de pistas. Es una aproximación, no una huella exacta como la de Nmap.

Pistas que usa:
  - TTL de la respuesta al ping: cada sistema parte de un valor inicial típico (Windows 128, Linux/Mac 64...)
    y baja 1 por cada router que cruza el paquete.
  - Puertos típicos: 135/139/445/3389 casi siempre son Windows; 22 sin lo anterior suele ser Linux/Unix.
  - Textos de los servicios: "Ubuntu", "Microsoft-IIS/10.0", "Win64", versión de OpenSSH...
"""
from __future__ import annotations

import re

from .models import OSGuess, PortResult

WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986, 1433, 5357, 49152, 49153, 49154}
IIS_VERSIONS = {"10.0": "Windows 10/11 o Windows Server 2016-2022", "8.5": "Windows Server 2012 R2",
                "8.0": "Windows Server 2012", "7.5": "Windows 7 o Windows Server 2008 R2",
                "7.0": "Windows Vista o Windows Server 2008", "6.0": "Windows Server 2003"}
UBUNTU_BY_OPENSSH = {"9.6": "Ubuntu 24.04", "9.3": "Ubuntu 23.10", "9.0": "Ubuntu 22.10", "8.9": "Ubuntu 22.04",
                     "8.4": "Ubuntu 21.04", "8.2": "Ubuntu 20.04", "7.6": "Ubuntu 18.04", "7.2": "Ubuntu 16.04",
                     "6.6": "Ubuntu 14.04"}
DEBIAN_BY_TAG = {"deb12": "Debian 12", "deb11": "Debian 11", "deb10": "Debian 10", "deb9": "Debian 9"}


def initial_ttl(observed: int) -> int:
    for start in (32, 64, 128, 255):
        if observed <= start:
            return start
    return 255


def guess_os(ttl: int | None, ports: list[PortResult]) -> OSGuess | None:
    """Devuelve una suposición del sistema operativo o None si no hay ninguna pista."""
    score = {"Windows": 0, "Linux/Unix": 0, "Dispositivo de red": 0, "macOS/BSD": 0}
    reasons: list[str] = []
    detail = ""
    open_ports = [p for p in ports if p.state == "open"]
    open_numbers = {p.port for p in open_ports if p.protocol == "tcp"}

    if ttl is not None:
        start = initial_ttl(ttl)
        hops = start - ttl
        if start == 128 or start == 32:
            score["Windows"] += 3
        elif start == 64:
            score["Linux/Unix"] += 2
            score["macOS/BSD"] += 1
        else:
            score["Dispositivo de red"] += 2
            score["Linux/Unix"] += 1
        reasons.append(f"TTL {ttl} (valor inicial probable {start}, {hops} saltos de distancia)")

    win_hits = sorted(open_numbers & WINDOWS_PORTS)
    if win_hits:
        score["Windows"] += 3 if len(win_hits) >= 2 else 2
        reasons.append("puertos típicos de Windows abiertos: " + ", ".join(map(str, win_hits)))
    elif 22 in open_numbers:
        score["Linux/Unix"] += 1
        reasons.append("SSH abierto sin puertos de Windows")

    for p in open_ports:
        text = f"{p.product} {p.version} {p.extrainfo} {p.banner}"
        low = text.lower()
        if "ubuntu" in low:
            score["Linux/Unix"] += 3
            m = re.search(r"OpenSSH.*?(\d+\.\d+)", f"{p.product} {p.version}")
            version = UBUNTU_BY_OPENSSH.get(m.group(1)) if m else None
            detail = version or "Ubuntu"
            reasons.append(f"el servicio del puerto {p.port} menciona Ubuntu")
        elif "debian" in low or "raspbian" in low:
            score["Linux/Unix"] += 3
            tag = next((v for k, v in DEBIAN_BY_TAG.items() if k in low), "")
            detail = tag or "Debian"
            reasons.append(f"el servicio del puerto {p.port} menciona Debian")
        elif "centos" in low or "red hat" in low or "rhel" in low or "fedora" in low:
            score["Linux/Unix"] += 3
            detail = "familia Red Hat"
            reasons.append(f"el servicio del puerto {p.port} menciona Red Hat/CentOS")
        elif "freebsd" in low or "openbsd" in low or "netbsd" in low:
            score["macOS/BSD"] += 3
            detail = "BSD"
            reasons.append(f"el servicio del puerto {p.port} menciona BSD")
        elif "microsoft-iis" in low or "microsoft iis" in low or p.product == "Microsoft-IIS" or "win64" in low \
                or "win32" in low or "microsoft windows" in low or "microsoft terminal" in low:
            score["Windows"] += 3
            m = re.search(r"IIS[/ ](\d+\.\d+)", text, re.I)
            if m and m.group(1) in IIS_VERSIONS:
                detail = IIS_VERSIONS[m.group(1)]
            reasons.append(f"el servicio del puerto {p.port} es de Microsoft/Windows")
        elif "mikrotik" in low or "routeros" in low or "cisco" in low or "ubiquiti" in low or "fortinet" in low:
            score["Dispositivo de red"] += 3
            detail = p.product or ""
            reasons.append(f"el servicio del puerto {p.port} parece de un equipo de red")
        elif "openssh" in low and "apple" in low:
            score["macOS/BSD"] += 3
            reasons.append("OpenSSH de Apple")

    best = max(score, key=score.get)
    if score[best] == 0:
        return None
    ordered = sorted(score.values(), reverse=True)
    lead = ordered[0] - ordered[1]
    confidence = "alta" if score[best] >= 6 and lead >= 3 else ("media" if score[best] >= 3 and lead >= 2 else "baja")
    return OSGuess(best, detail, confidence, reasons)
