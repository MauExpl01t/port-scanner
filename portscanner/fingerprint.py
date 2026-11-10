"""Detección de servicios y versiones (-sV).

Para cada puerto abierto:
  1. Se conecta y *escucha*: muchos servicios (SSH, FTP, SMTP, MySQL...) saludan primero.
  2. Si no dicen nada, se prueban "sondas" (una petición HTTP, un PING de Redis, un saludo TLS...) y se
     compara la respuesta con una tabla de firmas.
  3. Si nada coincide, se queda con el nombre que corresponde al número de puerto, marcado como no confirmado.
La intensidad (0-9) decide cuántas sondas se prueban: 0 = solo escuchar, 9 = todas.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from . import netio
from .ports import service_name

TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 2376, 3269, 5061, 5986, 6443, 8443, 9443,
             10250, 4443, 7443}
HTTP_PORTS = {80, 81, 443, 591, 800, 888, 1080, 2082, 2083, 2087, 3000, 3128, 4443, 4848, 5000, 5601, 5800,
              6443, 7001, 7443, 8000, 8008, 8009, 8080, 8081, 8083, 8086, 8088, 8161, 8200, 8443, 8500, 8800,
              8880, 8888, 9000, 9001, 9090, 9200, 9300, 9443, 10000, 10250, 15672, 2375, 2376, 16992}
SILENT_PORTS = HTTP_PORTS | {6379, 11211, 5432, 3389, 389, 554, 5060, 445, 139}

HTTP_GET = (b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: portscanner/1.0\r\nAccept: */*\r\n"
            b"Connection: close\r\n\r\n")
SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x2f\xffSMBr\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x0c\x00\x02NT LM 0.12\x00")
X224_REQUEST = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
LDAP_BIND = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
PG_SSLREQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"


@dataclass
class ServiceInfo:
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tls: bool = False
    confirmed: bool = False
    banner: str = ""
    tls_version: str = ""
    notes: list[str] = field(default_factory=list)


def _text(data: bytes, limit: int = 200) -> str:
    return netio.printable(data, limit)


def _host_bytes(name: str) -> bytes:
    """Nombre de host listo para la cabecera HTTP Host (soporta nombres con tildes)."""
    try:
        return name.encode("idna")
    except UnicodeError:
        return name.encode("ascii", "ignore")


# ---------- reconocedores por protocolo ----------
def _ssh(m: re.Match) -> ServiceInfo:
    soft = m.group("soft").decode("latin-1").strip()
    info = ServiceInfo("ssh", confirmed=True, banner=_text(m.group(0)))
    proto = m.group("proto").decode()
    mm = re.match(r"(?P<prod>[A-Za-z][\w.]*?)[_-](?P<ver>\d[\w.]*)(?:\s+(?P<rest>.*))?$", soft)
    if mm:
        info.product, info.version = mm.group("prod"), mm.group("ver")
        rest = mm.group("rest") or ""
    else:
        info.product, rest = soft, ""
    info.extrainfo = "; ".join(x for x in (rest, f"protocolo {proto}") if x)
    return info


def _smtp_ftp(m: re.Match) -> ServiceInfo | None:
    line = m.string.decode("latin-1")
    first = line.splitlines()[0][:150] if line else ""
    low = line.lower()
    if "smtp" in low or "mail service" in low or "postfix" in low or "exim" in low or "sendmail" in low:
        info = ServiceInfo("smtp", confirmed=True, banner=first)
        for pat, name in ((r"Postfix", "Postfix smtpd"), (r"Exim (\d[\d.]*)", "Exim smtpd"),
                          (r"Sendmail (\d[\d./]*)", "Sendmail"), (r"Microsoft ESMTP MAIL", "Microsoft ESMTP"),
                          (r"hMailServer", "hMailServer"), (r"Exchange", "Microsoft Exchange smtpd")):
            mm = re.search(pat, line, re.I)
            if mm:
                info.product = name
                info.version = mm.group(1) if mm.groups() else ""
                break
        return info
    ftp_names = (("vsFTPd", r"vsFTPd (\d[\w.]*)"), ("ProFTPD", r"ProFTPD (\d[\w.]*)"),
                 ("Pure-FTPd", None), ("FileZilla Server", r"FileZilla Server (?:version )?(\d[\w.]*)"),
                 ("Microsoft ftpd", None), ("Serv-U", None), ("wu-", None), ("FTP", None))
    for key, pat in ftp_names:
        if key.lower() in low:
            info = ServiceInfo("ftp", confirmed=True, banner=first)
            if key != "FTP":
                info.product = key
                if pat:
                    mm = re.search(pat, line, re.I)
                    info.version = mm.group(1) if mm else ""
            return info
    return None


def _pop3(m: re.Match) -> ServiceInfo:
    line = m.string.decode("latin-1").splitlines()[0][:150]
    info = ServiceInfo("pop3", confirmed=True, banner=line)
    if re.search("dovecot", line, re.I):
        info.product = "Dovecot pop3d"
    return info


def _imap(m: re.Match) -> ServiceInfo:
    line = m.string.decode("latin-1").splitlines()[0][:150]
    info = ServiceInfo("imap", confirmed=True, banner=line)
    for key in ("Dovecot", "Cyrus", "Courier"):
        if key.lower() in line.lower():
            info.product = f"{key} imapd"
    return info


def _mysql(m: re.Match) -> ServiceInfo:
    ver = m.group("ver").decode("latin-1")
    info = ServiceInfo("mysql", confirmed=True, banner=f"protocolo 10, versión {ver}")
    if "mariadb" in ver.lower():
        mm = re.search(r"(\d+\.\d+\.\d+)-MariaDB", ver) or re.search(r"(\d+\.\d+\.\d+)", ver)
        info.product, info.version = "MariaDB", (mm.group(1) if mm else ver)
    else:
        info.product, info.version = "MySQL", ver.split("-")[0]
        if "-" in ver:
            info.extrainfo = ver.split("-", 1)[1]
    return info


def _vnc(m: re.Match) -> ServiceInfo:
    major, minor = int(m.group(1)), int(m.group(2))
    return ServiceInfo("vnc", "VNC", extrainfo=f"protocolo {major}.{minor}", confirmed=True, banner=_text(m.group(0)))


def _redis(m: re.Match) -> ServiceInfo:
    word = m.group(1)
    extra = {b"+PONG": "responde sin pedir contraseña", b"-NOAUTH": "requiere autenticación",
             b"-DENIED": "acceso denegado (modo protegido)"}.get(word, "")
    return ServiceInfo("redis", "Redis key-value store", extrainfo=extra, confirmed=True, banner=_text(m.group(0)))


SIGNATURES: list[tuple[re.Pattern, object]] = [
    (re.compile(rb"^SSH-(?P<proto>\d\.\d+)-(?P<soft>[^\r\n]*)"), _ssh),
    (re.compile(rb"^RFB (\d{3})\.(\d{3})"), _vnc),
    (re.compile(rb"^(\+PONG|-NOAUTH|-DENIED|-ERR wrong number|-ERR unknown command)"), _redis),
    (re.compile(rb"^.{3}\x00\x0a(?P<ver>[\x20-\x7e]{3,60}?)\x00", re.S), _mysql),
    (re.compile(rb"is not allowed to connect to this (?:MySQL|MariaDB) server"),
     lambda m: ServiceInfo("mysql", "MySQL", extrainfo="rechaza este equipo", confirmed=True, banner=_text(m.group(0)))),
    (re.compile(rb"^VERSION (\S+)"),
     lambda m: ServiceInfo("memcached", "Memcached", m.group(1).decode(), confirmed=True, banner=_text(m.group(0)))),
    (re.compile(rb"^\xff[\xfb-\xfe]"), lambda m: ServiceInfo("telnet", confirmed=True, banner="(negociación telnet)")),
    (re.compile(rb"^\x03\x00..\x0e\xd0", re.S),
     lambda m: ServiceInfo("ms-wbt-server", "Microsoft Terminal Services", confirmed=True, banner="(RDP)")),
    (re.compile(rb"^\x00\x00..(?:\xffSMB|\xfeSMB)", re.S),
     lambda m: ServiceInfo("microsoft-ds", "Microsoft Windows SMB", confirmed=True, banner="(SMB)")),
    (re.compile(rb"^SIP/2\.0"), lambda m: ServiceInfo("sip", confirmed=True, banner=_text(m.group(0)))),
    (re.compile(rb"^RTSP/1\.0"), lambda m: ServiceInfo("rtsp", confirmed=True, banner=_text(m.group(0)))),
    (re.compile(rb"^AMQP"), lambda m: ServiceInfo("amqp", confirmed=True, banner=_text(m.group(0)))),
    (re.compile(rb"^\x30.{1,3}\x02\x01\x01\x61", re.S), lambda m: ServiceInfo("ldap", confirmed=True, banner="(LDAP)")),
    (re.compile(rb"^:\S+ (?:NOTICE|\d{3}) "), lambda m: ServiceInfo("irc", confirmed=True, banner=_text(m.group(0)))),
    (re.compile(rb"^\+OK"), _pop3),
    (re.compile(rb"^\* OK"), _imap),
    (re.compile(rb"^(?:220|421)[ -]"), _smtp_ftp),
]


def parse_http(data: bytes) -> ServiceInfo | None:
    m = re.match(rb"HTTP/(\d(?:\.\d)?) (\d{3})", data)
    if not m:
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        k, sep, v = line.partition(b":")
        if sep:
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    info = ServiceInfo("http", confirmed=True)
    info.banner = _text(head.split(b"\r\n")[0] + b" " + (b"Server: " + headers["server"].encode("latin-1")
                                                          if "server" in headers else b""))
    server = headers.get("server", "")
    if server:
        mm = re.match(r"([A-Za-z][\w.\-]*)(?:/([\w.\-]+))?\s*(?:\((.*?)\))?", server)
        if mm:
            info.product, info.version = mm.group(1), mm.group(2) or ""
            info.extrainfo = mm.group(3) or ""
    powered = headers.get("x-powered-by", "")
    if powered:
        info.extrainfo = "; ".join(x for x in (info.extrainfo, f"X-Powered-By: {powered}") if x)
    text = body.decode("utf-8", "replace").lower()
    if '"tagline" : "you know, for search"' in text or '"tagline":"you know, for search"' in text:
        info.product, info.extrainfo = "Elasticsearch", "API REST"
    elif '"apiversion"' in text and '"gitcommit"' in text:
        info.product, info.extrainfo = "Docker Engine API", "API REST"
    if not info.product and "www-authenticate" in headers:
        info.extrainfo = f"autenticación: {headers['www-authenticate'].split()[0]}"
    return info


def match_banner(data: bytes) -> ServiceInfo | None:
    """Compara bytes recibidos con las firmas conocidas."""
    if not data:
        return None
    http = parse_http(data)
    if http:
        return http
    for pattern, handler in SIGNATURES:
        m = pattern.search(data[:2048])
        if m:
            info = handler(m)
            if info is not None:
                return info
    # PostgreSQL responde con un solo byte S/N al SSLRequest, o con un error propio
    if data in (b"S", b"N") or re.match(rb"^E.{4}SFATAL|^E.{4}SERROR", data, re.S):
        return ServiceInfo("postgresql", "PostgreSQL", confirmed=True, banner="(PostgreSQL)")
    return None


@dataclass(frozen=True)
class Probe:
    name: str
    payload: bytes | None
    rarity: int
    ports: frozenset[int] | None = None   # si tiene puertos, es una sonda "dirigida" a esos puertos


PROBES = [
    Probe("GetRequest", b"", 1),                          # se rellena con el Host al usarla
    Probe("Redis", b"*1\r\n$4\r\nPING\r\n", 3, frozenset({6379, 6380, 26379})),
    Probe("Memcached", b"version\r\n", 4, frozenset({11211})),
    Probe("PostgreSQL", PG_SSLREQUEST, 4, frozenset({5432, 5433})),
    Probe("RDP", X224_REQUEST, 4, frozenset({3389})),
    Probe("SMB", SMB1_NEGOTIATE, 5, frozenset({445, 139})),
    Probe("LDAP", LDAP_BIND, 5, frozenset({389, 3268})),
    Probe("RTSP", b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", 5, frozenset({554, 8554})),
    Probe("SIP", b"OPTIONS sip:nm SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n", 6, frozenset({5060})),
    Probe("Generic", b"\r\n\r\n", 3),
    Probe("Help", b"HELP\r\n", 6),
]


def _plan(port: int, intensity: int) -> list[Probe]:
    chosen = []
    for p in PROBES:
        if p.ports is not None:
            if port in p.ports or intensity >= 9:
                chosen.append(p)
        elif p.rarity <= intensity:
            chosen.append(p)
    # primero las dirigidas a este puerto y luego por rareza
    chosen.sort(key=lambda p: (0 if (p.ports and port in p.ports) else 1, p.rarity))
    return chosen


async def _tls_service(host: str, port: int, timeout: float, hostname: str, intensity: int) -> ServiceInfo | None:
    """Intenta el saludo TLS; si funciona, mira qué protocolo viaja dentro."""
    writer = None
    sni = hostname or None
    try:
        reader, writer = await netio.open_stream(host, port, timeout, tls=True, server_hostname=sni)
    except netio.CONNECT_ERRORS:
        return None
    try:
        obj = writer.get_extra_info("ssl_object")
        version = obj.version() if obj else ""
        data = await netio.read_some(reader, 0.5)
        info = match_banner(data)
        if info is None:
            writer.write(HTTP_GET % _host_bytes(hostname or host))
            try:
                await asyncio.wait_for(writer.drain(), timeout)
            except netio.CONNECT_ERRORS:
                pass
            info = match_banner(await netio.read_some(reader, timeout))
    finally:
        await netio.close_stream(writer)
    out = info or ServiceInfo("", confirmed=False)
    inner = out.name
    out.name = "https" if inner == "http" else (f"ssl/{inner}" if inner else "ssl")
    out.tls, out.tls_version, out.confirmed = True, version, True
    return out


async def detect_service(host: str, port: int, *, intensity: int = 7, timeout: float = 3.0,
                         hostname: str = "") -> ServiceInfo:
    """Averigua qué servicio corre en un puerto TCP abierto."""
    guess = service_name(port, "tcp")
    fallback = ServiceInfo(guess, confirmed=False)
    if intensity < 0:
        return fallback
    host_header = _host_bytes(hostname or host)

    # 1) Escuchar: los servicios que "saludan primero"
    null_wait = min(timeout, 0.4 if port in SILENT_PORTS else 1.5)
    banner = await netio.exchange(host, port, None, timeout, wait=null_wait)
    info = match_banner(banner)
    if info:
        return info
    if banner:
        fallback.banner = _text(banner)

    if intensity == 0:
        return fallback

    # 2) TLS primero en puertos típicos de TLS
    tried_tls = False
    if port in TLS_PORTS and intensity >= 2:
        tried_tls = True
        tls_info = await _tls_service(host, port, timeout, hostname, intensity)
        if tls_info:
            return tls_info

    # 3) Sondas
    for probe in _plan(port, intensity):
        payload = HTTP_GET % host_header if probe.name == "GetRequest" else probe.payload
        data = await netio.exchange(host, port, payload, timeout, wait=min(timeout, 1.5))
        info = match_banner(data)
        if info:
            return info
        if data and not fallback.banner:
            fallback.banner = _text(data)
        if data and probe.name == "GetRequest" and b"HTTPS" in data.upper() and b"HTTP" in data.upper():
            fallback.notes.append("responde que espera HTTPS")

    # 4) TLS en puertos no típicos (si aún no se probó)
    if not tried_tls and intensity >= 2:
        tls_info = await _tls_service(host, port, timeout, hostname, intensity)
        if tls_info:
            return tls_info
    return fallback
