"""Interfaz de línea de comandos: python -m portscanner scan <objetivo> ..."""
from __future__ import annotations

import argparse
import asyncio
import os
import shlex
import sys
import time

from . import __version__, dnsutil
from .models import SEVERITIES
from .ports import PortSpecError, parse_ports, top_ports
from .report import to_grepable, to_html, to_json, to_text, to_xml
from .scanner import ScanOptions, new_result, run_scan
from .scripts import ScriptError, list_scripts, select_scripts
from .targets import TargetError, expand_targets, read_target_file
from .timing import get_timing

LEGAL = ("AVISO: escanea únicamente equipos propios o con autorización escrita del responsable. "
         "Escanear sin permiso puede ser delito.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="portscanner", allow_abbrev=False,
                                description="Escáner de puertos TCP/UDP. " + LEGAL,
                                epilog="Ejemplos:\n  python -m portscanner scan 192.168.1.10 --i-have-authorization\n"
                                       "  python -m portscanner scan 192.168.1.0/24 -p 22,80,443 --i-have-authorization\n"
                                       "  python -m portscanner scan midominio.cl -p- -sV -sC --i-have-authorization",
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"portscanner {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-scripts", help="Muestra los scripts disponibles y sus categorías")

    s = sub.add_parser("scan", help="Escanea uno o varios equipos", allow_abbrev=False,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("targets", nargs="*", help="IP, nombre, red (10.0.0.0/24) o rango (10.0.0.1-50)")
    s.add_argument("--i-have-authorization", action="store_true", required=True,
                   help="Confirma que tienes autorización para escanear estos equipos (obligatorio)")
    s.add_argument("--i-accept-large-scan", action="store_true", help="Permite escanear más de 256 equipos")
    s.add_argument("-iL", "--input-list", metavar="ARCHIVO", help="Archivo con un objetivo por línea")
    s.add_argument("--exclude", metavar="LISTA", help="Objetivos a excluir, separados por coma")

    g = s.add_argument_group("qué puertos")
    g.add_argument("-p", "--ports", metavar="LISTA", help="Ej.: 80 | 22,80,443 | 1-1000 | - (todos) | T:22,U:53")
    g.add_argument("-F", "--fast", action="store_true", help="Solo los 100 puertos más comunes")
    g.add_argument("--top-ports", type=int, metavar="N", help="Los N puertos más comunes")

    g = s.add_argument_group("técnicas de escaneo")
    g.add_argument("-sT", dest="scan_connect", action="store_true", help="TCP connect (por defecto)")
    g.add_argument("-sS", dest="scan_syn", action="store_true", help="TCP SYN (necesita scapy, Npcap y administrador)")
    g.add_argument("-sU", dest="scan_udp", action="store_true", help="Escaneo UDP (más lento)")
    g.add_argument("-sn", dest="ping_only", action="store_true", help="Solo descubrir equipos activos, sin escanear puertos")

    g = s.add_argument_group("descubrimiento de equipos")
    g.add_argument("-Pn", dest="no_ping", action="store_true", help="No descubrir: tratar todos los equipos como activos")
    g.add_argument("-PE", dest="ping_icmp", action="store_true", help="Usar solo ping (eco ICMP)")
    g.add_argument("-PS", dest="ping_tcp", metavar="PUERTOS", help="Usar conexiones TCP a estos puertos (ej.: 22,80,443)")

    g = s.add_argument_group("servicios, sistema operativo y scripts")
    g.add_argument("-sV", dest="service_detection", action="store_true", help="Detectar servicios y versiones")
    g.add_argument("--version-intensity", type=int, default=7, metavar="0-9", help="Cuántas sondas probar (por defecto 7)")
    g.add_argument("-O", dest="os_detection", action="store_true", help="Adivinar el sistema operativo")
    g.add_argument("-sC", dest="default_scripts", action="store_true", help="Ejecutar los scripts por defecto")
    g.add_argument("--script", metavar="LISTA", help="Scripts o categorías (default, safe, vuln, all) separados por coma")
    g.add_argument("-A", dest="aggressive", action="store_true", help="Agresivo: -sV -O -sC y traceroute")
    g.add_argument("--traceroute", action="store_true", help="Mostrar la ruta hasta el equipo")

    g = s.add_argument_group("velocidad y red")
    g.add_argument("-T", dest="timing", type=int, default=3, metavar="0-5", help="Plantilla de velocidad (0 lento, 5 rápido; por defecto 3)")
    g.add_argument("--timeout", type=float, metavar="SEG", help="Espera por puerto, en segundos")
    g.add_argument("--retries", type=int, metavar="N", help="Reintentos cuando no hay respuesta")
    g.add_argument("--concurrency", type=int, metavar="N", help="Conexiones simultáneas")
    g.add_argument("--delay", type=float, metavar="SEG", help="Pausa entre intentos")
    g.add_argument("--parallel-hosts", type=int, default=4, metavar="N", help="Equipos a escanear a la vez (por defecto 4)")
    g.add_argument("-n", dest="no_dns", action="store_true", help="No hacer búsqueda inversa de nombres (DNS)")
    g.add_argument("--dns-server", metavar="IP", help="Servidor DNS propio para resolver nombres")

    g = s.add_argument_group("salida")
    g.add_argument("--format", choices=["text", "json", "xml", "grepable", "html"], default="text")
    g.add_argument("-o", "--output", metavar="ARCHIVO", help="Guardar el resultado en un archivo")
    g.add_argument("-oN", dest="out_text", metavar="ARCHIVO", help="Guardar también en texto")
    g.add_argument("-oJ", dest="out_json", metavar="ARCHIVO", help="Guardar también en JSON")
    g.add_argument("-oX", dest="out_xml", metavar="ARCHIVO", help="Guardar también en XML")
    g.add_argument("-oG", dest="out_grep", metavar="ARCHIVO", help="Guardar también en formato grepable")
    g.add_argument("-oH", dest="out_html", metavar="ARCHIVO", help="Guardar también en HTML")
    g.add_argument("-oA", dest="out_all", metavar="BASE", help="Guardar en todos los formatos (BASE.txt/.json/.xml/.gnmap/.html)")
    g.add_argument("-v", dest="verbose", action="count", default=0, help="Más detalle (-v muestra también los puertos cerrados)")
    g.add_argument("--reason", action="store_true", help="Mostrar la razón de cada estado")
    g.add_argument("--open", dest="open_only", action="store_true", help="Mostrar solo puertos abiertos")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--no-progress", action="store_true", help="No mostrar la barra de progreso")
    g.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERIDAD",
                   help="Salir con código 2 si hay hallazgos de esta severidad o más graves")
    return p


_OUTPUT_FLAGS = {"-o", "--output", "-oN", "-oJ", "-oX", "-oG", "-oH", "-oA"}


def safe_command(argv: list[str]) -> str:
    """Comando para dejar en el informe, sin rutas de archivos (pueden revelar usuarios o carpetas del equipo)."""
    out: list[str] = []
    skip = False
    for item in argv:
        if skip:
            skip = False
            continue
        if item in _OUTPUT_FLAGS:
            skip = True               # se omite la bandera y su ruta de salida
            continue
        if item in ("-iL", "--input-list"):
            out += [item, "<archivo>"]
            skip = True
            continue
        out.append(item)
    return "portscanner " + " ".join(shlex.quote(a) for a in out)


def _eprint(*args) -> None:
    print(*args, file=sys.stderr)


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    _eprint(f"Guardado: {path}")


def _enable_ansi() -> bool:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        os.system("")       # activa los colores ANSI en la consola de Windows 10+
    return True


class Progress:
    """Línea de progreso en stderr (se reescribe sobre sí misma)."""

    def __init__(self, enabled: bool):
        self.enabled = enabled and sys.stderr.isatty()
        self.last = 0.0
        self.shown = False

    def __call__(self, host: str, label: str, done: int, total: int) -> None:
        if not self.enabled or time.monotonic() - self.last < 0.25 and done != total:
            return
        self.last = time.monotonic()
        pct = 100 * done // total if total else 100
        sys.stderr.write(f"\r  {host} {label}: {done}/{total} ({pct}%)   ")
        sys.stderr.flush()
        self.shown = True

    def clear(self) -> None:
        if self.shown:
            sys.stderr.write("\r" + " " * 70 + "\r")
            sys.stderr.flush()
            self.shown = False


def _cmd_list_scripts() -> int:
    print(f"{'SCRIPT':<22}{'PROTO':<7}{'CATEGORÍAS':<17}DESCRIPCIÓN")
    for sc in list_scripts():
        print(f"{sc.name:<22}{sc.protocol:<7}{','.join(sorted(sc.categories)):<17}{sc.description}")
    print("\nUsa --script <nombre|categoría>[,...]. '-sC' ejecuta la categoría 'default'. Todos solo detectan; no modifican nada.")
    return 0


def _build_options(args) -> ScanOptions:
    raw_targets = list(args.targets)
    if args.input_list:
        raw_targets += read_target_file(args.input_list)
    exclude = [x for x in (args.exclude or "").replace(" ", ",").split(",") if x]
    dns_server = dnsutil.validate_server(args.dns_server) if args.dns_server else None
    targets = expand_targets(raw_targets, exclude, dns_server=dns_server, large_ok=args.i_accept_large_scan)

    if args.aggressive:
        args.service_detection = args.os_detection = args.default_scripts = args.traceroute = True

    do_udp = args.scan_udp
    do_tcp = args.scan_connect or args.scan_syn or not do_udp
    if args.ping_only:
        do_tcp = do_udp = False

    tcp_ports: list[int] = []
    udp_ports: list[int] = []
    if not args.ping_only:
        if args.ports:
            default_proto = "udp" if (do_udp and not do_tcp) else "tcp"
            tcp_ports, udp_ports = parse_ports(args.ports, default_proto)
            if do_udp and do_tcp and not any(x in args.ports.upper() for x in ("T:", "U:")):
                udp_ports = list(tcp_ports)          # sin prefijos y con -sT -sU: los mismos puertos para ambos
        elif args.top_ports:
            tcp_ports = top_ports(args.top_ports, "tcp") if do_tcp else []
            udp_ports = top_ports(args.top_ports, "udp") if do_udp else []
        else:
            n = 100 if args.fast else 1000
            tcp_ports = top_ports(n, "tcp") if do_tcp else []
            udp_ports = top_ports(min(n, 100), "udp") if do_udp else []
        if not do_tcp:
            tcp_ports = []
        if not do_udp:
            udp_ports = []
        if not tcp_ports and not udp_ports:
            raise PortSpecError("no hay puertos para escanear con esa combinación de opciones (revisa -p, -sT y -sU)")

    scripts = select_scripts(args.script, default=args.default_scripts)
    if not 0 <= args.version_intensity <= 9:
        raise ValueError("--version-intensity debe estar entre 0 y 9")
    if args.parallel_hosts < 1 or args.parallel_hosts > 64:
        raise ValueError("--parallel-hosts debe estar entre 1 y 64")
    timing = get_timing(args.timing, timeout=args.timeout, retries=args.retries, concurrency=args.concurrency,
                        delay=args.delay)

    ping_ports = None
    icmp = True
    if args.ping_icmp or args.ping_tcp:
        icmp = bool(args.ping_icmp)
        ping_ports = parse_ports(args.ping_tcp, "tcp")[0] if args.ping_tcp else []

    return ScanOptions(
        targets=targets, timing=timing, tcp_ports=tcp_ports, udp_ports=udp_ports, discovery=not args.no_ping,
        ping_only=args.ping_only, icmp=icmp, ping_ports=ping_ports, service_detection=args.service_detection,
        intensity=args.version_intensity, os_detection=args.os_detection, scripts=scripts, traceroute=args.traceroute,
        resolve_names=not args.no_dns, dns_server=dns_server, use_syn=args.scan_syn, host_parallel=args.parallel_hosts,
        command=safe_command(getattr(args, "raw_argv", [])))


def _render(args, result, fmt: str, color: bool) -> str:
    include_closed = args.verbose >= 2
    if fmt == "json":
        return to_json(result, include_closed=include_closed)
    if fmt == "xml":
        return to_xml(result, include_closed=include_closed)
    if fmt == "grepable":
        return to_grepable(result)
    if fmt == "html":
        return to_html(result)
    return to_text(result, color=color, show_all=args.verbose >= 1, open_only=args.open_only, reason=args.reason)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    args.raw_argv = raw_argv
    if args.cmd == "list-scripts":
        return _cmd_list_scripts()

    try:
        opt = _build_options(args)
    except (TargetError, PortSpecError, ScriptError, dnsutil.DnsError, ValueError) as exc:
        _eprint(f"Error: {exc}")
        return 1
    if not args.targets and not args.input_list:
        _eprint("Error: indica al menos un objetivo (o usa -iL archivo.txt).")
        return 1

    _eprint(LEGAL)
    n_ports = len(opt.tcp_ports) + len(opt.udp_ports)
    _eprint(f"Equipos: {len(opt.targets)}   Puertos por equipo: {n_ports}   Velocidad: -T{opt.timing.level} ({opt.timing.name})")
    if opt.udp_ports and len(opt.udp_ports) > 1000:
        _eprint("Aviso: escanear muchos puertos UDP es MUY lento (cada puerto sin respuesta espera su tiempo límite).")
    if opt.use_syn:
        _eprint("Aviso: -sS es experimental y necesita scapy + Npcap + administrador; si falta, se usa -sT.")

    color = not args.no_color and not args.output and _enable_ansi()
    progress = Progress(not args.no_progress)
    log = (lambda m: _eprint(m)) if args.verbose else None
    result = new_result(opt)
    started = time.monotonic()
    try:
        asyncio.run(run_scan(opt, result, log=log, progress=progress))
    except KeyboardInterrupt:
        result.interrupted = True
    finally:
        progress.clear()
    if not result.finished_at:
        from .scanner import now_iso
        result.finished_at = now_iso()
    _eprint(f"Listo en {time.monotonic() - started:.1f} s.")

    primary = _render(args, result, args.format, color)
    if args.output:
        _write(args.output, primary)
    else:
        print(primary)
    extras = {"text": args.out_text, "json": args.out_json, "xml": args.out_xml, "grepable": args.out_grep, "html": args.out_html}
    if args.out_all:
        base = args.out_all
        extras = {"text": base + ".txt", "json": base + ".json", "xml": base + ".xml", "grepable": base + ".gnmap",
                  "html": base + ".html"}
    for fmt, path in extras.items():
        if path:
            _write(path, _render(args, result, fmt, False))

    if result.interrupted:
        return 130
    if args.fail_on:
        limit = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) <= limit for f in result.findings if f.severity in SEVERITIES):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
