"""Orquestador: junta descubrimiento, escaneo TCP/UDP, servicios, SO, scripts y hallazgos."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import dnsutil, risk, syn
from .discovery import Discovery, discover_hosts, icmp_ping
from .fingerprint import detect_service
from .models import HostResult, PortResult, ScanResult, ScriptResult
from .osguess import guess_os
from .scripts import Script, ScriptContext, run_script
from .targets import Target
from .tcp import scan_ports
from .timing import Timing
from .traceroute import traceroute
from .udp import scan_udp_ports

LogFn = Callable[[str], None]
ProgressFn = Callable[[str, str, int, int], None]      # (host, etiqueta, hechos, total)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanOptions:
    targets: list[Target]
    timing: Timing
    tcp_ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    discovery: bool = True               # False = -Pn (tratar todos como activos)
    ping_only: bool = False              # -sn
    icmp: bool = True
    ping_ports: list[int] | None = None
    service_detection: bool = False
    intensity: int = 7
    os_detection: bool = False
    scripts: list[Script] = field(default_factory=list)
    traceroute: bool = False
    resolve_names: bool = True
    dns_server: str | None = None
    use_syn: bool = False
    host_parallel: int = 4
    command: str = ""

    def checks_run(self) -> list[str]:
        out = []
        if self.discovery:
            out.append("host-discovery")
        if self.tcp_ports:
            out.append("tcp-syn" if self.use_syn else "tcp-connect")
        if self.udp_ports:
            out.append("udp")
        if self.service_detection:
            out.append("service-detection")
        if self.os_detection:
            out.append("os-detection")
        out.extend(f"script:{s.name}" for s in self.scripts)
        if self.traceroute:
            out.append("traceroute")
        return out


def new_result(opt: ScanOptions) -> ScanResult:
    return ScanResult(targets=[t.name or t.address for t in opt.targets], started_at=now_iso(),
                      checks_run=opt.checks_run(), hosts_total=len(opt.targets), command=opt.command)


async def _reverse_names(hosts: list[HostResult], dns_server: str | None) -> None:
    loop = asyncio.get_running_loop()

    async def one(h: HostResult) -> None:
        if h.hostname:
            return
        try:
            h.hostname = await asyncio.wait_for(loop.run_in_executor(None, dnsutil.reverse, h.address, dns_server), 3.0)
        except (asyncio.TimeoutError, TimeoutError):
            pass

    await asyncio.gather(*(one(h) for h in hosts))


def _apply_service(port: PortResult, info) -> None:
    if info.name:
        port.service = info.name
    port.product, port.version, port.extrainfo = info.product, info.version, info.extrainfo
    port.tls, port.confirmed = info.tls, info.confirmed
    if info.banner:
        port.banner = info.banner


async def _scan_host(host: HostResult, target: Target, opt: ScanOptions, script_findings: list,
                     errors: list[str], log: LogFn | None, progress: ProgressFn | None, parallel: int) -> None:
    timing = opt.timing
    concurrency = max(50, timing.concurrency // max(1, parallel))
    tcp_sink: dict[int, PortResult] = {}
    udp_sink: dict[int, PortResult] = {}
    addr = host.address

    def prog(label: str):
        return (lambda done, total: progress(addr, label, done, total)) if progress else None

    try:
        if opt.tcp_ports:
            from . import ports as _ports
            order = _ports.shuffled(opt.tcp_ports)
            if opt.use_syn:
                ok, why = syn.availability()
                if ok:
                    for r in await syn.syn_scan(addr, order, timing.timeout):
                        tcp_sink[r.port] = r
                else:
                    msg = f"-sS no disponible ({why}); se usa el modo connect (-sT)."
                    if msg not in errors:
                        errors.append(msg)
            if not tcp_sink:
                await scan_ports(addr, order, timing, concurrency=concurrency, progress=prog("TCP"), sink=tcp_sink)
        if opt.udp_ports:
            from . import ports as _ports
            await scan_udp_ports(addr, _ports.shuffled(opt.udp_ports), timing, concurrency=min(concurrency, 300),
                                 progress=prog("UDP"), sink=udp_sink)
    except asyncio.CancelledError:
        host.ports = sorted([*tcp_sink.values(), *udp_sink.values()], key=lambda p: (p.protocol, p.port))
        raise

    host.ports = sorted([*tcp_sink.values(), *udp_sink.values()], key=lambda p: (p.protocol, p.port))
    if addr.startswith("127.") or addr == "::1":
        host.notes.append("Escaneaste localhost: los servicios abiertos pueden estar limitados a este equipo. Para ver lo que "
                          "ven los demás, escanea la IP de tu red (por ejemplo 192.168.x.x).")
    open_tcp = [p for p in host.ports if p.protocol == "tcp" and p.state == "open"]
    if log:
        log(f"{addr}: {len(open_tcp)} puertos TCP abiertos")

    need_sv = opt.service_detection or bool(opt.scripts) or opt.os_detection
    if open_tcp and need_sv:
        sem = asyncio.Semaphore(16)

        async def sv(p: PortResult) -> None:
            async with sem:
                try:
                    info = await detect_service(addr, p.port, intensity=opt.intensity if opt.service_detection else 3,
                                                timeout=max(timing.timeout, 2.5), hostname=target.name)
                    _apply_service(p, info)
                except Exception as exc:        # un servicio raro no debe romper el resto
                    errors.append(f"detección de servicio en {addr}:{p.port} falló: {exc}")
        await asyncio.gather(*(sv(p) for p in open_tcp))

    if opt.scripts:
        sem = asyncio.Semaphore(8)

        async def run_one(sc: Script, p: PortResult) -> None:
            ctx = ScriptContext(host=addr, port=p.port, protocol=p.protocol, service=p.service, product=p.product,
                                version=p.version, banner=p.banner, tls=p.tls, hostname=target.name,
                                timeout=max(timing.timeout, 2.5))
            if not sc.applies(ctx):
                return
            async with sem:
                try:
                    out = await run_script(sc, ctx)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    errors.append(f"script {sc.name} en {addr}:{p.port} falló: {type(exc).__name__}: {exc}")
                    return
            if out and (out.text or out.findings):
                p.scripts.append(ScriptResult(sc.name, out.text))
                script_findings.extend(out.findings)

        targets = [p for p in host.ports if p.state == "open"]
        await asyncio.gather(*(run_one(sc, p) for p in targets for sc in opt.scripts))
        for p in targets:
            p.scripts.sort(key=lambda s: s.name)

    if opt.os_detection:
        if host.ttl is None:
            ping = await icmp_ping(addr, timing.timeout)
            host.ttl = ping.ttl
        host.os_guess = guess_os(host.ttl, host.ports)
        if host.os_guess is None:
            host.notes.append("No hay pistas suficientes para adivinar el sistema operativo.")

    if opt.traceroute:
        hops, err = await traceroute(addr, timeout=min(timing.timeout, 2.0))
        host.traceroute = hops
        if err:
            host.notes.append(f"traceroute: {err}")


async def run_scan(opt: ScanOptions, result: ScanResult | None = None, *, log: LogFn | None = None,
                   progress: ProgressFn | None = None) -> ScanResult:
    """Ejecuta el escaneo completo. Si se cancela (Ctrl+C) devuelve lo que ya se había encontrado."""
    result = result or new_result(opt)
    script_findings: list = []
    try:
        addresses = [t.address for t in opt.targets]
        if opt.discovery:
            if log:
                log(f"Descubriendo cuáles de los {len(addresses)} equipos están activos...")
            found = await discover_hosts(
                addresses, icmp=opt.icmp, tcp_ports=opt.ping_ports,
                timeout=min(opt.timing.timeout, 2.0), parallel=128 if len(addresses) > 1 else 1,
                progress=(lambda d, t: progress("-", "descubrimiento", d, t)) if progress else None)
        else:
            found = {a: Discovery(True, "user-set") for a in addresses}

        by_addr = {t.address: t for t in opt.targets}
        for a in addresses:
            d = found.get(a, Discovery())
            result.hosts.append(HostResult(address=a, hostname=by_addr[a].name, up=d.up, reason=d.reason,
                                           latency_ms=d.latency_ms, ttl=d.ttl, mac=d.mac))
        up_hosts = [h for h in result.hosts if h.up]
        if not up_hosts:
            result.errors.append("Ningún equipo respondió al descubrimiento. Si sabes que está encendido, prueba -Pn "
                                 "(salta el descubrimiento: el firewall puede estar bloqueando el ping).")
        if opt.resolve_names and up_hosts:
            await _reverse_names(up_hosts, opt.dns_server)

        if not opt.ping_only and up_hosts:
            parallel = max(1, min(opt.host_parallel, len(up_hosts)))
            sem = asyncio.Semaphore(parallel)

            async def guarded(h: HostResult) -> None:
                async with sem:
                    if log:
                        log(f"Escaneando {h.address}...")
                    await _scan_host(h, by_addr[h.address], opt, script_findings, result.errors, log, progress, parallel)

            await asyncio.gather(*(guarded(h) for h in up_hosts))
    except asyncio.CancelledError:
        result.interrupted = True
        result.errors.append("Escaneo interrumpido: los resultados pueden estar incompletos.")
    result.finished_at = now_iso()
    result.findings = risk.build_findings([h for h in result.hosts if h.up], script_findings)
    return result
