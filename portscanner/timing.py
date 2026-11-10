"""Plantillas de velocidad -T0 a -T5 (como Nmap): más lento = más discreto y más fiable."""
from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Timing:
    level: int
    name: str
    concurrency: int      # conexiones a la vez
    timeout: float        # segundos de espera por puerto
    retries: int          # reintentos cuando no hay respuesta
    delay: float          # pausa (s) entre intentos de un mismo trabajador


TEMPLATES = {
    0: Timing(0, "paranoico", 1, 10.0, 2, 3.0),
    1: Timing(1, "sigiloso", 3, 6.0, 2, 1.0),
    2: Timing(2, "educado", 20, 4.0, 2, 0.2),
    3: Timing(3, "normal", 400, 2.0, 1, 0.0),
    4: Timing(4, "agresivo", 700, 1.0, 1, 0.0),
    5: Timing(5, "insano", 1000, 0.6, 0, 0.0),
}

DEFAULT_LEVEL = 3
MAX_CONCURRENCY = 2000


def get_timing(level: int = DEFAULT_LEVEL, *, timeout: float | None = None, retries: int | None = None,
               concurrency: int | None = None, delay: float | None = None) -> Timing:
    if level not in TEMPLATES:
        raise ValueError("la plantilla de velocidad -T debe ser un número de 0 a 5")
    t = TEMPLATES[level]
    changes = {}
    if timeout is not None:
        if timeout <= 0 or timeout > 120:
            raise ValueError("--timeout debe estar entre 0 y 120 segundos")
        changes["timeout"] = float(timeout)
    if retries is not None:
        if retries < 0 or retries > 10:
            raise ValueError("--retries debe estar entre 0 y 10")
        changes["retries"] = int(retries)
    if concurrency is not None:
        if concurrency < 1 or concurrency > MAX_CONCURRENCY:
            raise ValueError(f"--concurrency debe estar entre 1 y {MAX_CONCURRENCY}")
        changes["concurrency"] = int(concurrency)
    if delay is not None:
        if delay < 0 or delay > 60:
            raise ValueError("--delay debe estar entre 0 y 60 segundos")
        changes["delay"] = float(delay)
    return replace(t, **changes) if changes else t
