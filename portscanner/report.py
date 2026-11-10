"""Formatos de salida: texto, JSON, XML, grepable y HTML."""
from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime

from . import __version__
from .models import SEVERITIES, HostResult, PortResult, ScanResult, compute_score

STATE_ES = {"open": "abierto", "closed": "cerrado", "filtered": "filtrado", "open|filtered": "abierto|filtrado"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_COLORS = {"CRITICAL": "1;31", "HIGH": "31", "MEDIUM": "33", "LOW": "36", "INFO": "37", "open": "32",
           "closed": "90", "filtered": "33", "open|filtered": "33", "dim": "90", "bold": "1"}


def _clean(text: str) -> str:
    return _CTRL.sub("", text or "")


def _paint(text: str, key: str, on: bool) -> str:
    return f"\033[{_COLORS[key]}m{text}\033[0m" if on and key in _COLORS else text


def duration(result: ScanResult) -> str:
    try:
        a, b = datetime.fromisoformat(result.started_at), datetime.fromisoformat(result.finished_at)
        secs = (b - a).total_seconds()
    except ValueError:
        return ""
    return f"{int(secs // 60)} min {int(secs % 60)} s" if secs >= 60 else f"{secs:.0f} s"


def shown_ports(host: HostResult, *, show_all: bool = False, open_only: bool = False) -> tuple[list[PortResult], Counter]:
    """Puertos que se muestran y el resumen (por estado/razón) de los que se ocultan."""
    interesting = [p for p in host.ports if p.state in ("open", "open|filtered")]
    others = [p for p in host.ports if p.state not in ("open", "open|filtered")]
    hidden: Counter = Counter()
    if open_only:
        hidden.update((p.state, p.reason) for p in others)
        return interesting, hidden
    if show_all or len(others) <= 15:
        return sorted(host.ports, key=lambda p: (p.protocol, p.port)), hidden
    hidden.update((p.state, p.reason) for p in others)
    return interesting, hidden


# ---------------- texto ----------------
def to_text(result: ScanResult, *, color: bool = False, show_all: bool = False, open_only: bool = False,
            reason: bool = False) -> str:
    out: list[str] = []
    out.append(_paint(f"PortScanner {__version__} — resultado del escaneo", "bold", color))
    out.append(f"Inicio: {result.started_at}   Fin: {result.finished_at or '-'}   Duración: {duration(result) or '-'}")
    out.append(f"Objetivos: {', '.join(result.targets)}")
    up = [h for h in result.hosts if h.up]
    out.append(f"Equipos activos: {len(up)} de {result.hosts_total}")
    if result.interrupted:
        out.append(_paint("⚠ ESCANEO INTERRUMPIDO: resultados parciales", "HIGH", color))
    for h in up:
        out.append("")
        title = h.address + (f" ({h.hostname})" if h.hostname and h.hostname != h.address else "")
        out.append(_paint(f"━━ {title} ━━", "bold", color))
        meta = [f"activo ({h.reason})" if h.reason else "activo"]
        if h.latency_ms is not None:
            meta.append(f"latencia {h.latency_ms:.1f} ms")
        if h.ttl is not None:
            meta.append(f"TTL {h.ttl}")
        if h.mac:
            meta.append(f"MAC {h.mac}")
        out.append("Estado: " + ", ".join(meta))
        if h.os_guess:
            out.append(f"Sistema operativo probable: {h.os_guess}")
            for r in h.os_guess.reasons:
                out.append(_paint(f"   · {r}", "dim", color))
        if h.ports:
            shown, hidden = shown_ports(h, show_all=show_all, open_only=open_only)
            out.append("")
            if shown:
                header = f"{'PUERTO':<11}{'ESTADO':<17}{'SERVICIO':<16}" + (f"{'RAZÓN':<18}" if reason else "") + "VERSIÓN"
                out.append(_paint(header, "dim", color))
            else:
                out.append("No se encontraron puertos abiertos.")
            for p in shown:
                svc = p.service + ("" if p.confirmed or p.state != "open" else "?")
                if p.tls and not svc.startswith(("https", "ssl")):
                    svc = "ssl/" + svc
                state = f"{STATE_ES.get(p.state, p.state):<17}"
                line = (f"{p.port}/{p.protocol:<8}"[:11].ljust(11) + _paint(state, p.state, color) + f"{svc:<16}"
                        + (f"{p.reason:<18}" if reason else "") + p.version_text)
                out.append(line.rstrip())
                for s in p.scripts:
                    lines = _clean(s.output).splitlines() or [""]
                    out.append(_paint(f"|  {s.name}: ", "dim", color) + lines[0])
                    out.extend(_paint("|    ", "dim", color) + extra for extra in lines[1:])
            for (state, why), n in sorted(hidden.items(), key=lambda kv: -kv[1]):
                out.append(_paint(f"(no se muestran {n} puertos {STATE_ES.get(state, state)}s — razón: {why}; "
                                  "usa -v para verlos)", "dim", color))
        elif result.hosts_total:
            out.append("No se escaneó ningún puerto en este equipo.")
        if h.traceroute:
            out.append("")
            out.append("TRACEROUTE (saltos hasta el equipo)")
            for hop in h.traceroute:
                rtt = f"{hop['rtt_ms']} ms" if hop.get("rtt_ms") is not None else "-"
                out.append(f"  {hop['hop']:>2}  {hop['address']:<40} {rtt}")
        for note in h.notes:
            out.append(_paint(f"Nota: {note}", "dim", color))
    down = [h for h in result.hosts if not h.up]
    if down:
        out.append("")
        if len(down) <= 5:
            out.append("Sin respuesta (apagados o con firewall): " + ", ".join(h.address for h in down))
        else:
            out.append(f"{len(down)} equipos sin respuesta (apagados o con firewall).")
    real = [f for f in result.findings if f.severity != "INFO"]
    if real:
        out.append("")
        out.append(_paint(f"HALLAZGOS DE SEGURIDAD ({len(real)}) — puntaje {compute_score(result.findings)}/100", "bold", color))
        for f in real:
            out.append(f"  [{_paint(f.severity, f.severity, color)}] {f.title}")
            if f.recommendation:
                out.append(_paint(f"      Qué hacer: {f.recommendation}", "dim", color))
    elif up and not result.interrupted:
        out.append("")
        out.append("No se detectaron servicios de riesgo conocido entre los puertos abiertos.")
    for err in result.errors:
        out.append(_paint(f"Aviso: {err}", "MEDIUM", color))
    return "\n".join(out)


# ---------------- JSON ----------------
def to_json(result: ScanResult, *, include_closed: bool = False) -> str:
    up = [h for h in result.hosts if h.up]
    hosts = []
    total_open = 0
    for h in up:
        data = h.to_dict()
        counts = Counter(p.state for p in h.ports)
        total_open += counts.get("open", 0)
        if not include_closed:
            data["ports"] = [p for p in data["ports"] if p["state"] in ("open", "open|filtered")]
        data["port_summary"] = dict(counts)
        hosts.append(data)
    doc = {
        "tool": "portscanner", "version": __version__, "command": result.command,
        "target": ", ".join(result.targets), "started_at": result.started_at, "finished_at": result.finished_at,
        "interrupted": result.interrupted, "score": compute_score(result.findings), "checks_run": result.checks_run,
        "errors": result.errors, "findings": [f.to_dict() for f in result.findings],
        "summary": {"hosts_total": result.hosts_total, "hosts_up": len(up), "open_ports": total_open},
        "hosts": hosts,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


# ---------------- XML ----------------
def to_xml(result: ScanResult, *, include_closed: bool = False) -> str:
    root = ET.Element("portscanrun", scanner="portscanner", version=__version__, args=_clean(result.command),
                      start=result.started_at, end=result.finished_at)
    for h in result.hosts:
        if not h.up:
            continue
        he = ET.SubElement(root, "host")
        ET.SubElement(he, "status", state="up", reason=_clean(h.reason))
        ET.SubElement(he, "address", addr=h.address, addrtype="ipv6" if ":" in h.address else "ipv4")
        if h.mac:
            ET.SubElement(he, "address", addr=h.mac, addrtype="mac")
        if h.hostname:
            ET.SubElement(ET.SubElement(he, "hostnames"), "hostname", name=_clean(h.hostname))
        pe = ET.SubElement(he, "ports")
        extra = Counter()
        for p in h.ports:
            if not include_closed and p.state not in ("open", "open|filtered"):
                extra[p.state] += 1
                continue
            pt = ET.SubElement(pe, "port", protocol=p.protocol, portid=str(p.port))
            ET.SubElement(pt, "state", state=p.state, reason=_clean(p.reason))
            attrs = {"name": _clean(p.service), "product": _clean(p.product), "version": _clean(p.version),
                     "extrainfo": _clean(p.extrainfo)}
            if p.tls:
                attrs["tunnel"] = "ssl"
            ET.SubElement(pt, "service", **{k: v for k, v in attrs.items() if v})
            for s in p.scripts:
                ET.SubElement(pt, "script", id=s.name, output=_clean(s.output))
        for state, n in extra.items():
            ET.SubElement(pe, "extraports", state=state, count=str(n))
        if h.os_guess:
            os_el = ET.SubElement(he, "os")
            ET.SubElement(os_el, "osmatch", name=_clean(h.os_guess.family + (f" ({h.os_guess.detail})" if h.os_guess.detail else "")),
                          accuracy=h.os_guess.confidence)
    ET.SubElement(root, "runstats", hosts_up=str(result.hosts_up), hosts_total=str(result.hosts_total))
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


# ---------------- grepable ----------------
def to_grepable(result: ScanResult) -> str:
    lines = [f"# PortScanner {__version__} escaneo iniciado {result.started_at} con: {_clean(result.command)}"]
    for h in result.hosts:
        name = f" ({h.hostname})" if h.hostname else ""
        if not h.up:
            lines.append(f"Host: {h.address}{name}\tStatus: Down")
            continue
        lines.append(f"Host: {h.address}{name}\tStatus: Up")
        ports = []
        ignored = Counter()
        for p in h.ports:
            if p.state in ("open", "open|filtered"):
                ports.append(f"{p.port}/{p.state}/{p.protocol}//{_clean(p.service)}//{_clean(p.version_text)}/")
            else:
                ignored[p.state] += 1
        row = f"Host: {h.address}{name}\tPorts: {', '.join(ports)}"
        if ignored:
            row += "\tIgnored State: " + ", ".join(f"{s} ({n})" for s, n in ignored.items())
        lines.append(row)
    lines.append(f"# Terminado: {result.hosts_up} equipos activos de {result.hosts_total}")
    return "\n".join(lines)


# ---------------- HTML ----------------
_HTML_CSS = """
:root{--bg:#f5f7fa;--card:#fff;--text:#1b2430;--muted:#5b6777;--line:#e2e7ee;--accent:#0f766e;
--crit:#b91c1c;--high:#dc2626;--med:#d97706;--low:#0369a1;--info:#64748b;--ok:#15803d}
@media(prefers-color-scheme:dark){:root{--bg:#0f1720;--card:#17212d;--text:#e6ebf2;--muted:#9aa7b8;--line:#263445;--accent:#2dd4bf}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 48px}h1{margin:0 0 4px}h2{margin:28px 0 10px;font-size:1.15rem}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.num{font-size:1.8rem;font-weight:700}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:.92rem}th{color:var(--muted);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:.78rem;font-weight:700;color:#fff}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}.LOW{background:var(--low)}.INFO{background:var(--info)}
.open{color:var(--ok);font-weight:600}pre{white-space:pre-wrap;margin:4px 0 0;font:.82rem/1.4 ui-monospace,Consolas,monospace;color:var(--muted)}
.finding{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;margin:10px 0}
@media print{body{background:#fff}.card,.finding,table{break-inside:avoid}}
"""


def to_html(result: ScanResult) -> str:
    e = lambda s: html.escape(_clean(str(s)), quote=True)   # noqa: E731
    up = [h for h in result.hosts if h.up]
    open_total = sum(1 for h in up for p in h.ports if p.state == "open")
    sev = Counter(f.severity for f in result.findings)
    parts = [f"<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Informe de puertos</title><style>{_HTML_CSS}</style></head><body><main>",
             f"<h1>Informe de puertos abiertos</h1><div class='muted'>Objetivos: {e(', '.join(result.targets))} · "
             f"{e(result.started_at)} · generado con PortScanner {__version__}</div>"]
    if result.interrupted:
        parts.append("<p class='card'><b>⚠ Escaneo interrumpido:</b> los resultados pueden estar incompletos.</p>")
    parts.append("<div class='grid'>"
                 f"<div class='card'><div class='num'>{len(up)}/{result.hosts_total}</div><div class='muted'>equipos activos</div></div>"
                 f"<div class='card'><div class='num'>{open_total}</div><div class='muted'>puertos abiertos</div></div>"
                 f"<div class='card'><div class='num'>{compute_score(result.findings)}</div><div class='muted'>puntaje (0-100)</div></div>"
                 f"<div class='card'><div class='num'>{sum(sev[s] for s in SEVERITIES if s != 'INFO')}</div><div class='muted'>hallazgos de riesgo</div></div></div>")
    for h in up:
        title = h.address + (f" ({h.hostname})" if h.hostname else "")
        parts.append(f"<h2>{e(title)}</h2>")
        meta = []
        if h.os_guess:
            meta.append(f"Sistema operativo probable: {e(str(h.os_guess))}")
        if h.mac:
            meta.append(f"MAC {e(h.mac)}")
        if meta:
            parts.append(f"<div class='muted'>{' · '.join(meta)}</div>")
        shown, hidden = shown_ports(h)
        if shown:
            parts.append("<table><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Versión / detalle</th></tr>")
            for p in shown:
                detail = e(p.version_text)
                for s in p.scripts:
                    detail += f"<pre>{e(s.name)}: {e(s.output)}</pre>"
                parts.append(f"<tr><td>{p.port}/{p.protocol}</td><td class='{'open' if p.state == 'open' else ''}'>"
                             f"{e(STATE_ES.get(p.state, p.state))}</td><td>{e(p.service)}</td><td>{detail}</td></tr>")
            parts.append("</table>")
        for (state, why), n in hidden.items():
            parts.append(f"<div class='muted'>{n} puertos {e(STATE_ES.get(state, state))}s no mostrados (razón: {e(why)})</div>")
    real = [f for f in result.findings if f.severity != "INFO"]
    parts.append(f"<h2>Hallazgos de seguridad ({len(real)})</h2>")
    for f in real:
        parts.append(f"<div class='finding'><span class='badge {e(f.severity)}'>{e(f.severity)}</span> <b>{e(f.title)}</b>"
                     f"<p>{e(f.description)}</p><p><b>Qué hacer:</b> {e(f.recommendation)}</p>"
                     + (f"<pre>{e(f.evidence)}</pre>" if f.evidence else "") + "</div>")
    if not real:
        parts.append("<p class='muted'>No se detectaron servicios de riesgo conocido.</p>")
    for err in result.errors:
        parts.append(f"<p class='muted'>Aviso: {e(err)}</p>")
    parts.append("<p class='muted'>Tip: para un informe explicado para el cliente final, genera el JSON y pásalo por "
                 "<code>report-generator</code>. Este informe es una fotografía del momento y no reemplaza una auditoría completa.</p>"
                 "</main></body></html>")
    return "".join(parts)
