import json
import xml.etree.ElementTree as ET

import pytest

from conftest import read_until
from portscanner.cli import build_parser, main, safe_command

AUTH = "--i-have-authorization"


def scan(capsys, *args):
    code = main(["scan", *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_exige_autorizacion():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "127.0.0.1", "-p", "80"])
    assert exc.value.code == 2


def test_sin_objetivo(capsys):
    code, _out, err = scan(capsys, AUTH)
    assert code == 1 and "objetivo" in err


@pytest.mark.parametrize("args,mensaje", [
    (["127.0.0.1", "-p", "99999"], "puertos"),
    (["127.0.0.1", "-p", "abc"], "puerto inválido"),
    (["127.0.0.1", "-T", "9"], "-T"),
    (["127.0.0.1", "--version-intensity", "12"], "intensity"),
    (["127.0.0.1", "--script", "inventado"], "inventado"),
    (["10.0.0.0/16"], "i-accept-large-scan"),
    (["0.0.0.0"], "cualquiera"),
    (["127.0.0.1", "--dns-server", "no-ip"], "dns-server"),
    (["127.0.0.1", "-sU", "-p", "T:80"], "combinación"),
    (["127.0.0.1", "--timeout", "-1"], "timeout"),
])
def test_errores_de_uso_dan_mensaje_claro(capsys, args, mensaje):
    code, _out, err = scan(capsys, *args, AUTH)
    assert code == 1 and mensaje in err and "Traceback" not in err


def test_escaneo_json(capsys, tcp_server, closed_port):
    srv = tcp_server(lambda c: c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"))
    code, out, _ = scan(capsys, "127.0.0.1", "-Pn", "-n", "-p", f"{srv.port},{closed_port}", "-sV", "-T4",
                        "--format", "json", AUTH)
    doc = json.loads(out)
    assert code == 0 and doc["summary"]["open_ports"] == 1
    p = doc["hosts"][0]["ports"][0]
    assert p["port"] == srv.port and p["service"] == "ssh" and p["version"] == "9.6"
    assert doc["hosts"][0]["port_summary"]["closed"] == 1


def test_salida_a_archivos(capsys, tcp_server, tmp_path):
    srv = tcp_server(lambda c: None)
    base = tmp_path / "res"
    code, _out, _err = scan(capsys, "127.0.0.1", "-Pn", "-n", "-p", str(srv.port), "-T4", "-oA", str(base), AUTH)
    assert code == 0
    for ext in (".txt", ".json", ".xml", ".gnmap", ".html"):
        assert (tmp_path / f"res{ext}").exists()
    json.loads((tmp_path / "res.json").read_text(encoding="utf-8"))
    ET.fromstring((tmp_path / "res.xml").read_text(encoding="utf-8"))
    assert "<!doctype html>" in (tmp_path / "res.html").read_text(encoding="utf-8")


def test_formato_y_archivo_de_salida(capsys, tcp_server, tmp_path):
    srv = tcp_server(lambda c: None)
    out_file = tmp_path / "x.xml"
    code, out, _ = scan(capsys, "127.0.0.1", "-Pn", "-n", "-p", str(srv.port), "-T4", "--format", "xml", "-o", str(out_file), AUTH)
    assert code == 0 and out == "" and out_file.exists()
    assert ET.fromstring(out_file.read_text(encoding="utf-8")).tag == "portscanrun"


def test_fail_on_con_hallazgo(capsys, tcp_server):
    def ftp(c):
        c.sendall(b"220 (vsFTPd 3.0.5)\r\n")
        read_until(c)
        c.sendall(b"331 pass\r\n")
        read_until(c)
        c.sendall(b"230 ok\r\n")
        read_until(c)
    srv = tcp_server(ftp)
    args = ["127.0.0.1", "-Pn", "-n", "-p", str(srv.port), "-sV", "-sC", "-T4", "--no-progress"]
    code, out, _ = scan(capsys, *args, "--fail-on", "HIGH", AUTH)
    assert code == 2 and "FTP" in out
    code, _out, _ = scan(capsys, *args, "--fail-on", "CRITICAL", AUTH)
    assert code == 0


def test_solo_descubrir_y_lista_de_objetivos(capsys, tcp_server, tmp_path):
    srv = tcp_server(lambda c: None)
    f = tmp_path / "t.txt"
    f.write_text("127.0.0.1\n", encoding="utf-8")
    code, out, _ = scan(capsys, "-iL", str(f), "-sn", "-PS", str(srv.port), "-n", AUTH)
    assert code == 0 and "Equipos activos: 1 de 1" in out and "PUERTO" not in out


def test_puertos_por_defecto_y_rapido():
    from portscanner.cli import _build_options
    p = build_parser()
    a = p.parse_args(["scan", "127.0.0.1", AUTH])
    assert len(_build_options(a).tcp_ports) == 1000
    a = p.parse_args(["scan", "127.0.0.1", "-F", AUTH])
    assert len(_build_options(a).tcp_ports) == 100
    a = p.parse_args(["scan", "127.0.0.1", "-p-", AUTH])
    assert len(_build_options(a).tcp_ports) == 65535
    a = p.parse_args(["scan", "127.0.0.1", "-sU", "-p", "53,161", AUTH])
    o = _build_options(a)
    assert o.udp_ports == [53, 161] and o.tcp_ports == []
    a = p.parse_args(["scan", "127.0.0.1", "-sT", "-sU", "-p", "53", AUTH])
    o = _build_options(a)
    assert o.udp_ports == [53] and o.tcp_ports == [53]
    a = p.parse_args(["scan", "127.0.0.1", "-A", AUTH])
    o = _build_options(a)
    assert o.service_detection and o.os_detection and o.traceroute and o.scripts


def test_list_scripts(capsys):
    assert main(["list-scripts"]) == 0
    assert "redis-noauth" in capsys.readouterr().out


def test_comando_guardado_no_incluye_rutas():
    cmd = safe_command(["scan", "10.0.0.5", "-p", "80", "-o", r"C:\Users\ana\x.json", "-oA", "base",
                        "-iL", "objetivos.txt", "--i-have-authorization"])
    assert cmd == "portscanner scan 10.0.0.5 -p 80 -iL '<archivo>' --i-have-authorization"
    assert "ana" not in cmd and "base" not in cmd


def test_el_json_registra_el_comando_sin_ruta(capsys, tcp_server, tmp_path):
    srv = tcp_server(lambda c: None)
    out_file = tmp_path / "secreto_usuario" / "r.json"
    out_file.parent.mkdir()
    code, _out, _err = scan(capsys, "127.0.0.1", "-Pn", "-n", "-p", str(srv.port), "-T4", "--format", "json",
                            "-o", str(out_file), AUTH)
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert code == 0 and "secreto_usuario" not in doc["command"] and "scan 127.0.0.1" in doc["command"]
