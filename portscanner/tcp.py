"""Escaneo TCP "connect": intenta abrir una conexión normal a cada puerto.

  - La conexión se establece         -> abierto
  - El equipo responde "rechazado"   -> cerrado   (el equipo está vivo, pero nadie escucha ahí)
  - No hay respuesta (timeout)       -> filtrado  (un firewall probablemente descarta los paquetes)
"""
from __future__ import annotations

import asyncio
import errno
import socket
import sys
import time
from collections import deque
from typing import Callable

from .models import CLOSED, FILTERED, OPEN, PortResult
from .ports import service_name
from .timing import Timing

# Códigos de error de Windows (WSA*) y de Linux/macOS que significan "no hay ruta hasta ese equipo".
_UNREACHABLE = {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065, 1231, 1232}
_REFUSED = {errno.ECONNREFUSED, 10061, 1225}
_RESET = {errno.ECONNRESET, 10054, 1236, 64}
# El propio equipo se quedó sin sockets o puertos temporales: no es culpa del objetivo.
_LOCAL_LIMIT = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.EADDRNOTAVAIL, 10055, 10048, 10047, 10024}

ProgressFn = Callable[[int, int], None]

_SIO_TCP_INITIAL_RTO = 0x98000011


def _disable_syn_retransmissions(sock: socket.socket) -> None:
    """Windows reintenta el SYN 2 veces antes de avisar "rechazado" (un puerto cerrado tarda ~2 s en responder).
    Apagamos esos reintentos (como hace Nmap) para que cerrado y filtrado se distingan rápido."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        class RtoParams(ctypes.Structure):
            _fields_ = [("Rtt", ctypes.c_ushort), ("MaxSynRetransmissions", ctypes.c_ubyte)]

        params = RtoParams(0xFFFF, 0xFE)   # RTT sin especificar, sin retransmisiones de SYN
        returned = wintypes.DWORD(0)
        ws2 = ctypes.WinDLL("ws2_32", use_last_error=True)
        ws2.WSAIoctl.argtypes = [ctypes.c_size_t, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                 ctypes.c_void_p, ctypes.c_void_p]
        ws2.WSAIoctl(sock.fileno(), _SIO_TCP_INITIAL_RTO, ctypes.byref(params), ctypes.sizeof(params),
                     None, 0, ctypes.byref(returned), None, None)
    except Exception:
        pass   # Windows antiguo: seguimos con el comportamiento normal


async def try_connect(host: str, port: int, timeout: float) -> None:
    """Abre y cierra una conexión TCP. Lanza la excepción de red correspondiente si falla."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    # En IPv6 el bucle de Windows exige la dirección completa (con flowinfo y scope_id)
    address = (socket.getaddrinfo(host, port, family, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)[0][4]
               if family == socket.AF_INET6 else (host, port))
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        _disable_syn_retransmissions(sock)
        await asyncio.wait_for(loop.sock_connect(sock, address), timeout)
    finally:
        sock.close()


def _os_code(exc: OSError) -> int | None:
    return getattr(exc, "winerror", None) or exc.errno


async def probe_port(host: str, port: int, timing: Timing, local_limit_hits: list[int] | None = None) -> PortResult:
    """Prueba un puerto TCP y devuelve su estado."""
    result = PortResult(port=port, protocol="tcp", state=FILTERED, reason="no-response",
                        service=service_name(port, "tcp"))
    attempts = timing.retries + 1
    local_retries = 0
    attempt = 0
    while attempt < attempts:
        attempt += 1
        try:
            await try_connect(host, port, timing.timeout)
            result.state, result.reason = OPEN, "conn-established"
            return result
        except (asyncio.TimeoutError, TimeoutError):
            result.state, result.reason = FILTERED, "no-response"
        except ConnectionRefusedError:
            result.state, result.reason = CLOSED, "conn-refused"
            return result
        except ConnectionResetError:
            result.state, result.reason = CLOSED, "reset"
            return result
        except OSError as exc:
            code = _os_code(exc)
            if code in _REFUSED:
                result.state, result.reason = CLOSED, "conn-refused"
                return result
            if code in _RESET:
                result.state, result.reason = CLOSED, "reset"
                return result
            if code in _UNREACHABLE:
                result.state, result.reason = FILTERED, "host-unreachable"
                return result
            if code in _LOCAL_LIMIT:
                # Nos quedamos sin recursos locales: esperamos un poco y volvemos a intentar sin gastar un intento.
                if local_limit_hits is not None:
                    local_limit_hits.append(1)
                local_retries += 1
                if local_retries <= 8:
                    attempt -= 1
                    await asyncio.sleep(0.15 * local_retries)
                    continue
                result.state, result.reason = FILTERED, "local-resource-limit"
                return result
            if code in (5, errno.EACCES, 10013):
                result.state, result.reason = FILTERED, "blocked-locally"      # el sistema o el firewall local lo impide
                return result
            result.state, result.reason = FILTERED, f"error-{code}"
            return result
        if attempt < attempts and timing.delay:
            await asyncio.sleep(timing.delay)
    return result


async def scan_ports(host: str, ports: list[int], timing: Timing, *, concurrency: int | None = None,
                     progress: ProgressFn | None = None,
                     sink: dict[int, PortResult] | None = None) -> list[PortResult]:
    """Escanea muchos puertos a la vez con un grupo de trabajadores. Devuelve los resultados ordenados.

    `sink` es un diccionario opcional donde se van guardando los resultados: si el escaneo se cancela
    (Ctrl+C) quien llamó conserva lo que ya se había descubierto.
    """
    pending = deque(ports)
    total = len(ports)
    done = 0
    results: dict[int, PortResult] = sink if sink is not None else {}
    local_hits: list[int] = []
    workers_n = max(1, min(concurrency or timing.concurrency, total or 1))
    last_report = 0.0

    async def worker() -> None:
        nonlocal done, last_report
        while pending:
            port = pending.popleft()
            results[port] = await probe_port(host, port, timing, local_hits)
            done += 1
            if progress:
                now = time.monotonic()
                if now - last_report >= 0.5 or done == total:
                    last_report = now
                    progress(done, total)
            if timing.delay and not pending:
                break
            if timing.delay:
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
