import asyncio
import struct

import pytest

from conftest import read_until
from portscanner import fingerprint, scripts
from portscanner.fingerprint import detect_service, match_banner
from portscanner.scripts import ScriptContext, ScriptError, select_scripts


def run(coro):
    return asyncio.run(coro)


# ---------- reconocer banners ----------
@pytest.mark.parametrize("data,name,product,version", [
    (b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", "ssh", "OpenSSH", "8.9p1"),
    (b"SSH-1.99-dropbear_2020.81\r\n", "ssh", "dropbear", "2020.81"),
    (b"220 mail.ejemplo.cl ESMTP Postfix (Ubuntu)\r\n", "smtp", "Postfix smtpd", ""),
    (b"220 mx ESMTP Exim 4.96 Fri, 01 Jan\r\n", "smtp", "Exim smtpd", "4.96"),
    (b"220 (vsFTPd 3.0.5)\r\n", "ftp", "vsFTPd", "3.0.5"),
    (b"220 ProFTPD 1.3.8 Server ready.\r\n", "ftp", "ProFTPD", "1.3.8"),
    (b"+OK Dovecot ready.\r\n", "pop3", "Dovecot pop3d", ""),
    (b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", "imap", "Dovecot imapd", ""),
    (b"RFB 003.008\n", "vnc", "VNC", ""),
    (b"+PONG\r\n", "redis", "Redis key-value store", ""),
    (b"-NOAUTH Authentication required.\r\n", "redis", "Redis key-value store", ""),
    (b"VERSION 1.6.21\r\n", "memcached", "Memcached", "1.6.21"),
    (b"\xff\xfd\x18\xff\xfd\x20", "telnet", "", ""),
    (b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00", "ms-wbt-server", "Microsoft Terminal Services", ""),
    (b"SIP/2.0 200 OK\r\nServer: Asterisk\r\n", "sip", "", ""),
    (b"AMQP\x00\x00\x09\x01", "amqp", "", ""),
    (b"N", "postgresql", "PostgreSQL", ""),
])
def test_match_banner(data, name, product, version):
    info = match_banner(data)
    assert info is not None and info.name == name and info.product == product and info.version == version
    assert info.confirmed


def test_match_banner_mysql_y_mariadb():
    mysql = b"\x4a\x00\x00\x00\x0a8.0.33-0ubuntu0.22.04.2\x00" + b"\x00" * 30
    info = match_banner(mysql)
    assert (info.name, info.product, info.version) == ("mysql", "MySQL", "8.0.33")
    maria = b"\x4a\x00\x00\x00\x0a5.5.5-10.6.12-MariaDB-1\x00" + b"\x00" * 30
    info = match_banner(maria)
    assert (info.product, info.version) == ("MariaDB", "10.6.12")


def test_match_banner_http_con_cabeceras():
    data = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nX-Powered-By: PHP/8.1\r\n\r\n<html></html>")
    info = match_banner(data)
    assert (info.name, info.product, info.version) == ("http", "nginx", "1.18.0")
    assert "Ubuntu" in info.extrainfo and "PHP/8.1" in info.extrainfo


def test_match_banner_elasticsearch_y_docker_por_cuerpo():
    es = b'HTTP/1.1 200 OK\r\n\r\n{"cluster_name":"x","tagline":"You Know, for Search"}'
    assert match_banner(es).product == "Elasticsearch"
    dk = b'HTTP/1.1 200 OK\r\n\r\n{"ApiVersion":"1.43","GitCommit":"abc"}'
    assert match_banner(dk).product == "Docker Engine API"


@pytest.mark.parametrize("data", [b"", b"hola mundo", b"\x00\x01\x02", b"HTTP/", b"SSH-"])
def test_match_banner_desconocido(data):
    assert match_banner(data) is None


# ---------- detectar contra servidores falsos ----------
def test_detect_ssh_http_mysql(tcp_server):
    ssh = tcp_server(lambda c: c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"))

    def http(c):
        read_until(c, b"\r\n\r\n")
        c.sendall(b"HTTP/1.1 200 OK\r\nServer: Caddy\r\n\r\nhola")
    web = tcp_server(http)
    info = run(detect_service("127.0.0.1", ssh.port, timeout=2))
    assert info.name == "ssh" and info.version == "9.6"
    info = run(detect_service("127.0.0.1", web.port, timeout=2))
    assert info.name == "http" and info.product == "Caddy"


def test_detect_redis_necesita_intensidad_alta_en_puerto_raro(tcp_server):
    def redis(c):
        if b"PING" in c.recv(100):
            c.sendall(b"+PONG\r\n")
    srv = tcp_server(redis)
    assert run(detect_service("127.0.0.1", srv.port, intensity=9, timeout=2)).name == "redis"
    low = run(detect_service("127.0.0.1", srv.port, intensity=0, timeout=2))
    assert not low.confirmed


def test_detect_desconocido_usa_nombre_por_puerto(tcp_server):
    srv = tcp_server(lambda c: None)
    info = run(detect_service("127.0.0.1", srv.port, intensity=3, timeout=1))
    assert info.confirmed is False


def test_detect_tls_https(tcp_server, tls_context_pair):
    def https(c):
        read_until(c, b"\r\n\r\n")
        c.sendall(b"HTTP/1.1 200 OK\r\nServer: miweb/2.0\r\n\r\nok")
    srv = tcp_server(https, tls_context=tls_context_pair)
    info = run(detect_service("127.0.0.1", srv.port, timeout=2))
    assert info.name == "https" and info.tls and info.product == "miweb"
    assert info.tls_version.startswith("TLS")


# ---------- scripts ----------
def ctx(port, **kw):
    return ScriptContext(host="127.0.0.1", port=port, timeout=2, **kw)


def test_seleccion_de_scripts():
    names = {s.name for s in select_scripts("default")}
    assert {"http-title", "ssl-cert", "ftp-anon"} <= names and "redis-noauth" not in names
    assert "redis-noauth" in {s.name for s in select_scripts("vuln")}
    assert {s.name for s in select_scripts("banner,smb-v1")} == {"banner", "smb-v1"}
    assert len(select_scripts("all")) == len(scripts.REGISTRY)
    assert select_scripts(None, default=True)
    with pytest.raises(ScriptError):
        select_scripts("no-existe")


def test_script_aplica_segun_servicio():
    ftp = scripts.REGISTRY["ftp-anon"]
    assert ftp.applies(ctx(21, service="ftp"))
    assert not ftp.applies(ctx(80, service="http"))
    title = scripts.REGISTRY["http-title"]
    assert title.applies(ctx(8080, service="http-proxy"))
    assert title.applies(ctx(443, service="https", tls=True))
    cert = scripts.REGISTRY["ssl-cert"]
    assert cert.applies(ctx(993, service="ssl/imap", tls=True))
    assert not cert.applies(ctx(22, service="ssh"))
    assert scripts.REGISTRY["snmp-public"].applies(ScriptContext("127.0.0.1", 161, "udp", "snmp"))
    assert not scripts.REGISTRY["snmp-public"].applies(ctx(161, service="snmp"))


def test_ftp_anonimo_detectado_y_rechazado(tcp_server):
    def ftp_open(c):
        c.sendall(b"220 Bienvenido\r\n")
        assert read_until(c).startswith(b"USER anonymous")
        c.sendall(b"331 Password\r\n")
        read_until(c)
        c.sendall(b"230 Login successful\r\n")
        read_until(c)

    def ftp_closed(c):
        c.sendall(b"220 Bienvenido\r\n")
        read_until(c)
        c.sendall(b"530 Login incorrect\r\n")
        read_until(c)
    ok, no = tcp_server(ftp_open), tcp_server(ftp_closed)
    sc = scripts.REGISTRY["ftp-anon"]
    out = run(sc.run(ctx(ok.port, service="ftp")))
    assert out.findings and out.findings[0].severity == "HIGH" and out.findings[0].port == ok.port
    out = run(sc.run(ctx(no.port, service="ftp")))
    assert not out.findings


def test_redis_sin_clave(tcp_server):
    def redis(c):
        data = c.recv(200)
        if b"INFO" in data:
            c.sendall(b"$40\r\n# Server\r\nredis_version:7.0.11\r\nos:Linux\r\n")
        elif b"PING" in data:
            c.sendall(b"+PONG\r\n")
            c.settimeout(1)
            try:
                c.recv(1)
            except OSError:
                pass
    srv = tcp_server(redis)
    out = run(scripts.REGISTRY["redis-noauth"].run(ctx(srv.port, service="redis")))
    assert out.findings[0].severity == "CRITICAL" and "7.0.11" in out.text

    locked = tcp_server(lambda c: (c.recv(100), c.sendall(b"-NOAUTH Authentication required.\r\n")))
    out = run(scripts.REGISTRY["redis-noauth"].run(ctx(locked.port, service="redis")))
    assert not out.findings and "contraseña" in out.text


def test_memcached_abierto(tcp_server):
    srv = tcp_server(lambda c: (c.recv(100), c.sendall(b"STAT pid 1\r\nSTAT version 1.6.9\r\nEND\r\n")))
    out = run(scripts.REGISTRY["memcached-open"].run(ctx(srv.port, service="memcached")))
    assert out.findings[0].severity == "HIGH" and "1.6.9" in out.text


def test_vnc_sin_autenticacion_y_con_clave(tcp_server):
    def vnc(types):
        def handler(c):
            c.sendall(b"RFB 003.008\n")
            c.recv(12)
            c.sendall(bytes([len(types)] + types))
        return handler
    open_srv, locked = tcp_server(vnc([1, 2])), tcp_server(vnc([2]))
    sc = scripts.REGISTRY["vnc-noauth"]
    out = run(sc.run(ctx(open_srv.port, service="vnc")))
    assert out.findings and out.findings[0].severity == "CRITICAL"
    out = run(sc.run(ctx(locked.port, service="vnc")))
    assert not out.findings and "Contraseña VNC" in out.text


def test_smb_v1_habilitado_y_solo_v2(tcp_server):
    v1 = tcp_server(lambda c: (c.recv(200), c.sendall(b"\x00\x00\x00\x25\xffSMBr\x00\x00\x00\x00" + b"\x00" * 30)))
    v2 = tcp_server(lambda c: (c.recv(200), c.sendall(b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 60)))
    sc = scripts.REGISTRY["smb-v1"]
    out = run(sc.run(ctx(v1.port, service="microsoft-ds")))
    assert out.findings and out.findings[0].severity == "HIGH"
    out = run(sc.run(ctx(v2.port, service="microsoft-ds")))
    assert not out.findings


def test_mongodb_sin_autenticacion(tcp_server):
    body = struct.pack("<I", 0) + b"\x00" + b"\x30\x00\x00\x00" + b"\x01totalSize\x00" + b"\x00" * 20
    reply = struct.pack("<iiii", 16 + len(body), 2, 1, 2013) + body
    srv = tcp_server(lambda c: (c.recv(300), c.sendall(reply)))
    out = run(scripts.REGISTRY["mongodb-noauth"].run(ctx(srv.port, service="mongod")))
    assert out.findings and out.findings[0].severity == "CRITICAL"
    # el mensaje enviado es un OP_MSG válido
    doc = scripts._bson_doc([("listDatabases", 1), ("$db", "admin")])
    assert struct.unpack("<i", doc[:4])[0] == len(doc) and doc.endswith(b"\x00")


def test_docker_y_elasticsearch(tcp_server):
    def respond(body):
        def handler(c):
            read_until(c, b"\r\n\r\n")
            c.sendall(b"HTTP/1.0 200 OK\r\n\r\n" + body)
        return handler
    dk = tcp_server(respond(b'{"ApiVersion":"1.43","Version":"24.0.5"}'))
    es = tcp_server(respond(b'{"cluster_name":"prod","tagline":"You Know, for Search"}'))
    out = run(scripts.REGISTRY["docker-api-exposed"].run(ctx(dk.port, service="docker")))
    assert out.findings[0].severity == "CRITICAL" and "24.0.5" in out.text
    out = run(scripts.REGISTRY["elasticsearch-open"].run(ctx(es.port, service="http")))
    assert out.findings[0].severity == "HIGH" and "prod" in out.text


def test_http_title_headers_y_metodos(tcp_server):
    def web(c):
        data = read_until(c, b"\r\n\r\n")
        if data.startswith(b"OPTIONS"):
            c.sendall(b"HTTP/1.0 200 OK\r\nAllow: GET, POST, PUT, DELETE, TRACE\r\n\r\n")
        else:
            c.sendall(b"HTTP/1.0 200 OK\r\nServer: Apache/2.4.1\r\n\r\n<html><title> Mi  Sitio </title></html>")
    srv = tcp_server(web)
    c = ctx(srv.port, service="http")
    assert "Mi Sitio" in run(scripts.REGISTRY["http-title"].run(c)).text
    out = run(scripts.REGISTRY["http-headers"].run(c))
    assert any(f.check.endswith("http-version-disclosure") for f in out.findings)
    out = run(scripts.REGISTRY["http-methods"].run(c))
    assert out.findings and out.findings[0].severity == "MEDIUM"


def test_ssl_cert_y_protocolos(tcp_server, tls_context_pair):
    srv = tcp_server(lambda c: c.recv(10), tls_context=tls_context_pair)
    out = run(scripts.REGISTRY["ssl-cert"].run(ctx(srv.port, service="https", tls=True)))
    assert "CN=localhost" in out.text and "SHA-256" in out.text
    assert any("autofirmado" in f.title for f in out.findings)     # el certificado de prueba es autofirmado
    out = run(scripts.REGISTRY["ssl-weak-protocols"].run(ctx(srv.port, service="https", tls=True)))
    assert "TLSv1.3: aceptado" in out.text or "TLSv1.2: aceptado" in out.text


def test_ssh_v1_y_version_antigua():
    sc = scripts.REGISTRY["ssh-protocol"]
    out = run(sc.run(ctx(22, service="ssh", banner="SSH-1.99-OpenSSH_6.6.1")))
    checks = {f.check for f in out.findings}
    assert "ports.script.ssh-v1" in checks and "ports.script.ssh-old-version" in checks
    out = run(sc.run(ctx(22, service="ssh", banner="SSH-2.0-OpenSSH_9.6")))
    assert not out.findings


def test_smtp_lista_comandos(tcp_server):
    def smtp(c):
        c.sendall(b"220 mx ESMTP\r\n")
        read_until(c)
        c.sendall(b"250-mx\r\n250-SIZE 100\r\n250 8BITMIME\r\n")
        read_until(c)
    srv = tcp_server(smtp)
    out = run(scripts.REGISTRY["smtp-commands"].run(ctx(srv.port, service="smtp")))
    assert "SIZE 100" in out.text and "8BITMIME" in out.text
    assert not out.findings          # el aviso de STARTTLS solo aplica a los puertos 25 y 587


def test_script_que_falla_no_rompe(tcp_server):
    srv = tcp_server(lambda c: None)
    out = run(scripts.REGISTRY["http-title"].run(ctx(srv.port, service="http")))
    assert out is None
    assert run(scripts.REGISTRY["redis-noauth"].run(ctx(srv.port, service="redis"))) is None
