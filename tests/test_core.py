import asyncio
import json
import xml.etree.ElementTree as ET

import pytest

from portscanner import discovery, osguess, report, risk, syn
from portscanner.models import Finding, HostResult, PortResult, ScanResult, compute_score
from portscanner.scanner import ScanOptions, new_result, run_scan
from portscanner.scripts import select_scripts
from portscanner.targets import Target
from portscanner.timing import get_timing
from portscanner.traceroute import parse_traceroute


def run(coro):
    return asyncio.run(coro)


def port(n, state="open", proto="tcp", service="unknown", **kw):
    return PortResult(n, proto, state, kw.pop("reason", "syn-ack"), service, **kw)


# ---------- ping / ARP / traceroute ----------
def test_parse_ping_windows_espanol_e_ingles():
    es = "Respuesta desde 192.168.1.10: bytes=32 tiempo=2ms TTL=64"
    assert discovery.parse_ping(es, "192.168.1.10") == (64, 2.0)
    en = "Reply from 192.168.1.10: bytes=32 time<1ms TTL=128"
    ttl, lat = discovery.parse_ping(en, "192.168.1.10")
    assert ttl == 128 and lat < 1


def test_parse_ping_linux_y_falsos_positivos():
    linux = "64 bytes from 10.0.0.5: icmp_seq=1 ttl=57 time=12.4 ms"
    assert discovery.parse_ping(linux, "10.0.0.5") == (57, 12.4)
    # el router responde "host inaccesible" con su propio TTL: no cuenta como respuesta del host
    assert discovery.parse_ping("Reply from 192.168.1.1: Destination host unreachable. TTL=64", "192.168.1.50") is None
    assert discovery.parse_ping("Request timed out.", "10.0.0.5") is None
    assert discovery.parse_ping("", "10.0.0.5") is None


def test_parse_arp_windows_y_linux():
    win = """
Interfaz: 192.168.1.20 --- 0x7
  Dirección de Internet          Dirección física      Tipo
  192.168.1.1           aa-bb-cc-dd-ee-ff     dinámico
  192.168.1.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
"""
    assert discovery.parse_arp(win) == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
    lin = "? (192.168.1.7) at 0:1a:2b:3c:4d:5e [ether] on eth0\n? (192.168.1.8) at <incomplete> on eth0"
    assert discovery.parse_arp(lin) == {"192.168.1.7": "00:1a:2b:3c:4d:5e"}


def test_descubrimiento_loopback_y_cerrado(tcp_server):
    srv = tcp_server(lambda c: None)
    found = run(discovery.discover_hosts(["127.0.0.1"], icmp=False, tcp_ports=[srv.port], timeout=1.0))
    assert found["127.0.0.1"].up and found["127.0.0.1"].reason == "syn-ack"
    # puerto cerrado en un equipo vivo: la conexión rechazada también prueba que el equipo existe
    found = run(discovery.discover_hosts(["127.0.0.1"], icmp=False, tcp_ports=[9], timeout=1.0))
    assert found["127.0.0.1"].up and found["127.0.0.1"].reason == "conn-refused"


def test_parse_traceroute_windows_y_linux():
    win = """
Traza a la dirección dns.google [8.8.8.8]
  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Tiempo de espera agotado.
  3    12 ms    11 ms    13 ms  8.8.8.8
Traza completa.
"""
    hops = parse_traceroute(win)
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[0]["address"] == "192.168.1.1" and hops[1]["address"] == "*" and hops[2]["rtt_ms"] == 12.0
    lin = " 1  10.0.0.1  0.412 ms\n 2  * \n 3  203.0.113.9  9.8 ms"
    assert [h["address"] for h in parse_traceroute(lin)] == ["10.0.0.1", "*", "203.0.113.9"]


# ---------- sistema operativo ----------
def test_os_por_ttl_y_puertos():
    g = osguess.guess_os(128, [port(445), port(3389)])
    assert g.family == "Windows" and g.confidence == "alta"
    g = osguess.guess_os(63, [port(22, product="OpenSSH", version="8.9p1", extrainfo="Ubuntu-3ubuntu0.6")])
    assert g.family == "Linux/Unix" and g.detail == "Ubuntu 22.04"
    assert osguess.guess_os(None, []) is None
    g = osguess.guess_os(None, [port(80, product="Microsoft-IIS", version="10.0")])
    assert g.family == "Windows" and "Windows" in g.detail
    assert osguess.initial_ttl(57) == 64 and osguess.initial_ttl(120) == 128 and osguess.initial_ttl(250) == 255


# ---------- hallazgos ----------
def host(addr="203.0.113.5", ports=()):
    return HostResult(address=addr, ports=list(ports))


def test_hallazgos_por_servicio_expuesto():
    h = host(ports=[port(23, service="telnet", confirmed=True), port(80, service="http"), port(3389, service="ms-wbt-server")])
    found = risk.build_findings([h], [])
    checks = {f.check for f in found}
    assert {"ports.telnet", "ports.rdp", "ports.inventory"} <= checks
    telnet = next(f for f in found if f.check == "ports.telnet")
    assert telnet.severity == "HIGH" and telnet.port == 23 and "203.0.113.5:23" in telnet.title
    assert found[0].severity in ("HIGH", "CRITICAL")           # ordenado de más grave a menos


def test_hallazgos_no_repite_lo_que_ya_dijo_un_script():
    h = host(ports=[port(6379, service="redis", confirmed=True)])
    sf = Finding("ports.script.redis-noauth", "Redis sin clave", "CRITICAL", "d", "r", host=h.address, port=6379, protocol="tcp")
    found = risk.build_findings([h], [sf])
    assert [f.check for f in found if f.port == 6379] == ["ports.script.redis-noauth"]


def test_hallazgos_localhost_no_alarma():
    h = host("127.0.0.1", [port(3306, service="mysql"), port(445, service="microsoft-ds")])
    assert not [f for f in risk.build_findings([h], []) if f.severity != "INFO"]


def test_muchos_puertos_abiertos():
    h = host(ports=[port(n) for n in range(1000, 1030)])
    assert any(f.check == "ports.many-open" for f in risk.build_findings([h], []))


def test_puntaje():
    fs = [Finding("a", "t", "CRITICAL", "d"), Finding("b", "t", "LOW", "d"), Finding("c", "t", "INFO", "d")]
    assert compute_score(fs) == 100 - 30 - 2
    assert compute_score([Finding("x", "t", "CRITICAL", "d")] * 9) == 0


# ---------- informes ----------
def sample_result():
    h = HostResult("203.0.113.5", hostname="srv.ejemplo.cl", reason="echo-reply", latency_ms=1.2, ttl=64,
                   ports=[port(22, service="ssh", product="OpenSSH", version="8.9", confirmed=True),
                          port(23, service="telnet"), port(25, "closed", reason="conn-refused"),
                          port(53, "open|filtered", "udp", reason="no-response")])
    h.ports[0].scripts = []
    r = ScanResult(["203.0.113.5"], "2026-11-09T10:00:00+00:00", "2026-11-09T10:00:07+00:00", [h],
                   checks_run=["tcp-connect"], hosts_total=2, command="portscanner scan 203.0.113.5")
    r.hosts.append(HostResult("203.0.113.6", up=False))
    r.findings = risk.build_findings([h], [])
    return r


def test_json_compatible_con_report_generator():
    doc = json.loads(report.to_json(sample_result()))
    assert doc["target"] == "203.0.113.5" and 0 <= doc["score"] <= 100
    f = doc["findings"][0]
    assert {"check", "title", "severity", "description", "recommendation", "evidence"} <= set(f)
    assert doc["summary"] == {"hosts_total": 2, "hosts_up": 1, "open_ports": 2}
    states = {p["state"] for p in doc["hosts"][0]["ports"]}
    assert states == {"open", "open|filtered"}               # sin puertos cerrados por defecto
    full = json.loads(report.to_json(sample_result(), include_closed=True))
    assert any(p["state"] == "closed" for p in full["hosts"][0]["ports"])


def test_xml_valido_y_escapado():
    r = sample_result()
    r.hosts[0].ports[0].product = 'Evil"<script>&\x00'
    root = ET.fromstring(report.to_xml(r))
    ports = root.findall("./host/ports/port")
    assert {p.get("portid") for p in ports} == {"22", "23", "53"}
    assert root.find("./host/ports/extraports").get("state") == "closed"


def test_grepable():
    text = report.to_grepable(sample_result())
    assert "Host: 203.0.113.5 (srv.ejemplo.cl)\tStatus: Up" in text
    assert "22/open/tcp//ssh//OpenSSH 8.9/" in text and "Status: Down" in text


def test_html_escapa_datos_hostiles():
    r = sample_result()
    r.hosts[0].hostname = "<script>alert(1)</script>"
    r.findings.append(Finding("x", "<img src=x onerror=alert(1)>", "HIGH", "d<b>", "r"))
    out = report.to_html(r)
    assert "<script>alert(1)</script>" not in out and "<img src=x" not in out
    assert "&lt;script&gt;" in out


def test_texto_resumen_y_colapso_de_cerrados():
    r = sample_result()
    out = report.to_text(r)
    assert "22/tcp" in out and "abierto" in out and "HALLAZGOS" in out and "sin respuesta" in out.lower()
    many = sample_result()
    many.hosts[0].ports += [port(n, "closed", reason="conn-refused") for n in range(100, 140)]
    assert "no se muestran 41 puertos cerrados" in report.to_text(many)
    assert "100/tcp" in report.to_text(many, show_all=True)


# ---------- escaneo completo ----------
def test_escaneo_completo_contra_servidor_falso(tcp_server):
    srv = tcp_server(lambda c: c.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"))
    opt = ScanOptions(targets=[Target("127.0.0.1")], timing=get_timing(4, timeout=1.0), tcp_ports=[srv.port, 9],
                      discovery=False, service_detection=True, os_detection=True, scripts=select_scripts("default"),
                      resolve_names=False)
    result = run(run_scan(opt))
    h = result.hosts[0]
    open_ports = [p for p in h.ports if p.state == "open"]
    assert len(open_ports) == 1 and open_ports[0].service == "ssh" and open_ports[0].version == "8.2p1"
    assert any(s.name == "ssh-protocol" for s in open_ports[0].scripts)
    assert h.os_guess is not None and result.finished_at and not result.interrupted
    assert result.checks_run[0] == "tcp-connect"


def test_escaneo_solo_descubrimiento(tcp_server):
    opt = ScanOptions(targets=[Target("127.0.0.1")], timing=get_timing(4, timeout=1.0), ping_only=True, icmp=False,
                      ping_ports=[9], resolve_names=False)
    result = run(run_scan(opt))
    assert result.hosts[0].up and not result.hosts[0].ports


def test_escaneo_equipo_caido_avisa_que_use_Pn(monkeypatch):
    async def none_up(addresses, **kw):
        return {a: discovery.Discovery() for a in addresses}
    monkeypatch.setattr("portscanner.scanner.discover_hosts", none_up)
    opt = ScanOptions(targets=[Target("127.0.0.1")], timing=get_timing(4), tcp_ports=[80], resolve_names=False)
    result = run(run_scan(opt))
    assert not result.hosts[0].up and any("-Pn" in e for e in result.errors)


def test_cancelacion_devuelve_parcial(monkeypatch):
    from portscanner import scanner

    async def slow_scan(host, ports, timing, **kw):
        kw["sink"][80] = port(80)
        await asyncio.sleep(30)
    monkeypatch.setattr(scanner, "scan_ports", slow_scan)
    opt = ScanOptions(targets=[Target("127.0.0.1")], timing=get_timing(4), tcp_ports=[80, 81], discovery=False,
                      resolve_names=False)
    result = new_result(opt)

    async def main():
        task = asyncio.create_task(run_scan(opt, result))
        await asyncio.sleep(0.5)
        task.cancel()
        return await task
    out = run(main())
    assert out.interrupted and out.hosts[0].ports and out.hosts[0].ports[0].port == 80


# ---------- SYN opcional ----------
def test_syn_no_disponible_sin_scapy(monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "scapy", None)
    monkeypatch.setitem(__import__("sys").modules, "scapy.all", None)
    ok, why = syn.availability()
    assert not ok and "scapy" in why


def test_syn_cae_a_connect(monkeypatch, tcp_server):
    srv = tcp_server(lambda c: None)
    monkeypatch.setattr(syn, "availability", lambda: (False, "falta scapy"))
    opt = ScanOptions(targets=[Target("127.0.0.1")], timing=get_timing(4, timeout=1.0), tcp_ports=[srv.port],
                      discovery=False, use_syn=True, resolve_names=False)
    result = run(run_scan(opt))
    assert result.hosts[0].ports[0].state == "open"
    assert any("-sS no disponible" in e for e in result.errors)
