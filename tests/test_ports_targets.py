import pytest

from portscanner import dnsutil
from portscanner.ports import PortSpecError, parse_ports, service_name, top_ports
from portscanner.targets import TargetError, expand_targets, read_target_file
from portscanner.timing import get_timing


# ---------- puertos ----------
def test_parse_ports_lista_y_rangos():
    assert parse_ports("80") == ([80], [])
    assert parse_ports("22,80,443") == ([22, 80, 443], [])
    assert parse_ports("1-5,10") == ([1, 2, 3, 4, 5, 10], [])
    assert parse_ports("5,3,3,1") == ([1, 3, 5], [])


def test_parse_ports_todos_y_abiertos():
    tcp, _ = parse_ports("-")
    assert tcp[0] == 1 and tcp[-1] == 65535 and len(tcp) == 65535
    assert parse_ports("-3")[0] == [1, 2, 3]
    assert parse_ports("65534-")[0] == [65534, 65535]


def test_parse_ports_prefijos_tcp_udp():
    assert parse_ports("T:22,80,U:53,161") == ([22, 80], [53, 161])
    assert parse_ports("53", default_protocol="udp") == ([], [53])


@pytest.mark.parametrize("bad", ["", "0", "65536", "abc", "10-5", "80,,443", "1-70000", "-5-"])
def test_parse_ports_invalidos(bad):
    with pytest.raises(PortSpecError):
        parse_ports(bad)


def test_top_ports():
    assert top_ports(3)[:3] == [80, 23, 443]
    assert len(top_ports(100)) == 100
    assert len(set(top_ports(1000))) == 1000
    assert len(top_ports(65535)) == 65535
    assert top_ports(10, "udp")[0] == 53
    with pytest.raises(PortSpecError):
        top_ports(0)


def test_service_name():
    assert service_name(22) == "ssh"
    assert service_name(53, "udp") == "domain"
    assert service_name(65000) == "unknown"


# ---------- objetivos ----------
def fake_resolver(name, server=None):
    table = {"servidor.local": ["10.0.0.7"], "v6.local": ["2001:db8::1"]}
    if name not in table:
        raise dnsutil.DnsError(f"no pude resolver {name!r}")
    return table[name]


def addrs(ts):
    return [t.address for t in ts]


def test_objetivos_ip_cidr_rango():
    assert addrs(expand_targets(["10.0.0.5"])) == ["10.0.0.5"]
    assert addrs(expand_targets(["10.0.0.0/30"])) == ["10.0.0.1", "10.0.0.2"]
    assert addrs(expand_targets(["10.0.0.1-3"])) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert addrs(expand_targets(["10.0.0-1.5"])) == ["10.0.0.5", "10.0.1.5"]
    assert addrs(expand_targets(["10.0.0.1,9"])) == ["10.0.0.1", "10.0.0.9"]
    assert addrs(expand_targets(["10.0.0.7/32"])) == ["10.0.0.7"]


def test_objetivos_nombre_y_duplicados():
    ts = expand_targets(["servidor.local", "10.0.0.7"], resolver=fake_resolver)
    assert addrs(ts) == ["10.0.0.7"]
    assert ts[0].name == "servidor.local"
    assert addrs(expand_targets(["v6.local"], resolver=fake_resolver)) == ["2001:db8::1"]


def test_objetivos_exclusiones():
    ts = expand_targets(["10.0.0.0/29"], exclude=["10.0.0.2", "10.0.0.4-5"])
    assert addrs(ts) == ["10.0.0.1", "10.0.0.3", "10.0.0.6"]
    with pytest.raises(TargetError):
        expand_targets(["10.0.0.5"], exclude=["10.0.0.5"])


def test_objetivos_limites():
    with pytest.raises(TargetError, match="i-accept-large-scan"):
        expand_targets(["10.0.0.0/23"])
    assert len(expand_targets(["10.0.0.0/23"], large_ok=True)) == 510
    with pytest.raises(TargetError, match="máximo"):
        expand_targets(["10.0.0.0/8"], large_ok=True)
    with pytest.raises(TargetError):
        expand_targets(["2001:db8::/32"], large_ok=True)


@pytest.mark.parametrize("bad", ["", "0.0.0.0", "255.255.255.255", "224.0.0.1", "300.1.1.1", "10.0.0.0/99",
                                 "10.0.0.9-2", "no es host", "::"])
def test_objetivos_invalidos(bad):
    with pytest.raises(TargetError):
        expand_targets([bad], resolver=fake_resolver)


def test_objetivo_que_no_resuelve():
    with pytest.raises(TargetError):
        expand_targets(["inexistente.local"], resolver=fake_resolver)
    with pytest.raises(TargetError):
        expand_targets([])


def test_archivo_de_objetivos(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# comentario\n10.0.0.1\n\n10.0.0.2 10.0.0.3  # mas\n", encoding="utf-8")
    assert read_target_file(str(f)) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    (tmp_path / "vacio.txt").write_text("# nada\n", encoding="utf-8")
    with pytest.raises(TargetError):
        read_target_file(str(tmp_path / "vacio.txt"))
    with pytest.raises(TargetError):
        read_target_file(str(tmp_path / "no-existe.txt"))


# ---------- velocidad ----------
def test_timing():
    assert get_timing(3).concurrency == 400
    assert get_timing(5).timeout < get_timing(1).timeout
    assert get_timing(4, timeout=5).timeout == 5
    with pytest.raises(ValueError):
        get_timing(9)
    with pytest.raises(ValueError):
        get_timing(3, timeout=0)
    with pytest.raises(ValueError):
        get_timing(3, concurrency=999999)


# ---------- DNS ----------
def test_dns_consulta_y_respuesta_con_compresion():
    q = dnsutil.build_query("ejemplo.cl", 1, 0x1234)
    assert q[:2] == b"\x12\x34" and q.endswith(b"\x00\x01\x00\x01")
    # respuesta: misma pregunta + 1 respuesta A con puntero de compresión al nombre (offset 12)
    resp = (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:] +
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22")
    rcode, answers = dnsutil.parse_response(resp, 0x1234)
    assert rcode == 0 and answers == [(1, "93.184.216.34")]
    with pytest.raises(dnsutil.DnsError):
        dnsutil.parse_response(resp, 0x9999)
    with pytest.raises(dnsutil.DnsError):
        dnsutil.parse_response(b"\x00\x01")


def test_dns_bucle_de_punteros():
    evil = b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c"
    with pytest.raises(dnsutil.DnsError):
        dnsutil.parse_response(evil)


def test_dns_servidor_invalido():
    with pytest.raises(dnsutil.DnsError):
        dnsutil.validate_server("no-es-ip")
    assert dnsutil.validate_server(" 8.8.8.8 ") == "8.8.8.8"
