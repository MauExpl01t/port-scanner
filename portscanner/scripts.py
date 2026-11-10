"""Scripts de comprobación (-sC / --script), al estilo NSE de Nmap pero en Python.

Reglas del juego (para que sean seguros):
  - Solo LEEN y DETECTAN: ninguno modifica datos, explota fallos ni adivina contraseñas.
  - Categorías: default (los que corre -sC), safe (no molestan al servicio) y vuln (detectan exposición).
  - Cada script devuelve un texto para mostrar y, opcionalmente, hallazgos con severidad.
"""
from __future__ import annotations

import asyncio
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

from . import netio
from .fingerprint import HTTP_PORTS, SMB1_NEGOTIATE
from .models import Finding
from .udp import snmp_get_sysdescr, udp_request


class ScriptError(ValueError):
    pass


@dataclass
class ScriptContext:
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    tls: bool = False
    hostname: str = ""
    timeout: float = 3.0

    @property
    def is_http(self) -> bool:
        base = self.service.split("/")[-1]
        return base.startswith("http") or self.service == "https" or (self.port in HTTP_PORTS and not self.service)

    def finding(self, check: str, title: str, severity: str, description: str, recommendation: str,
                evidence: str = "", reference: str = "") -> Finding:
        where = f"{self.host}:{self.port}/{self.protocol}"
        return Finding(f"ports.script.{check}", f"{title} ({where})", severity, description, recommendation, evidence,
                       reference, host=self.host, port=self.port, protocol=self.protocol)


@dataclass
class ScriptOutput:
    text: str = ""
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class Script:
    name: str
    categories: frozenset[str]
    description: str
    protocol: str
    services: frozenset[str]
    ports: frozenset[int]
    run: Callable[[ScriptContext], Awaitable[ScriptOutput | None]]

    def applies(self, ctx: ScriptContext) -> bool:
        if ctx.protocol != self.protocol:
            return False
        if not self.services and not self.ports:
            return True
        base = ctx.service.split("/")[-1].rstrip("?")
        if "http" in self.services and ctx.is_http:
            return True
        if "ssl" in self.services and ctx.tls:
            return True
        return base in self.services or ctx.port in self.ports


REGISTRY: dict[str, Script] = {}


def script(name: str, categories: str, description: str, *, services: str = "", ports: tuple[int, ...] = (),
           protocol: str = "tcp"):
    def decorator(fn):
        REGISTRY[name] = Script(name, frozenset(categories.split(",")), description, protocol,
                                frozenset(s for s in services.split(",") if s), frozenset(ports), fn)
        return fn
    return decorator


# ---------- utilidades ----------
async def http_fetch(ctx: ScriptContext, method: str = "GET", path: str = "/", limit: int = 16384):
    """Pide una URL y devuelve (código, cabeceras, cuerpo) o None."""
    host_header = (ctx.hostname or ctx.host).encode("ascii", "ignore")
    request = (f"{method} {path} HTTP/1.0\r\nHost: ".encode() + host_header +
               b"\r\nUser-Agent: portscanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    data = await netio.exchange(ctx.host, ctx.port, request, ctx.timeout, tls=ctx.tls,
                                server_hostname=ctx.hostname or None, limit=limit)
    m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", data)
    if not m:
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        k, sep, v = line.partition(b":")
        if sep:
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return int(m.group(1)), headers, body


class Session:
    """Conversación línea a línea con un servidor de texto (FTP, SMTP...)."""

    def __init__(self, reader, writer, timeout):
        self.reader, self.writer, self.timeout = reader, writer, timeout

    @classmethod
    async def open(cls, ctx: ScriptContext) -> "Session":
        reader, writer = await netio.open_stream(ctx.host, ctx.port, ctx.timeout, tls=ctx.tls,
                                                 server_hostname=ctx.hostname or None)
        return cls(reader, writer, ctx.timeout)

    async def recv(self, wait: float | None = None) -> str:
        data = await netio.read_some(self.reader, wait if wait is not None else self.timeout, 4096, grace=0.3)
        return data.decode("latin-1", "replace")

    async def send(self, line: str, wait: float | None = None) -> str:
        self.writer.write(line.encode("latin-1", "replace") + b"\r\n")
        await asyncio.wait_for(self.writer.drain(), self.timeout)
        return await self.recv(wait)

    async def close(self) -> None:
        await netio.close_stream(self.writer)


# ---------- scripts por defecto ----------
@script("banner", "default,safe", "Muestra el texto de bienvenida que da el servicio")
async def banner_script(ctx: ScriptContext):
    if ctx.banner:
        return ScriptOutput(ctx.banner)
    return None


@script("http-title", "default,safe", "Título de la página principal y código de respuesta", services="http")
async def http_title(ctx: ScriptContext):
    res = await http_fetch(ctx)
    if not res:
        return None
    status, headers, body = res
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:120] if m else "(sin título)"
    text = f"{title} [HTTP {status}]"
    if status in (301, 302, 303, 307, 308) and "location" in headers:
        text += f" → {headers['location'][:120]}"
    return ScriptOutput(text)


@script("http-headers", "default,safe", "Cabeceras que revelan el software del servidor", services="http")
async def http_headers(ctx: ScriptContext):
    res = await http_fetch(ctx, "HEAD") or await http_fetch(ctx)
    if not res:
        return None
    _status, headers, _ = res
    shown = [f"{k}: {headers[k]}" for k in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")
             if k in headers]
    findings = []
    if "x-aspnet-version" in headers or re.search(r"/\d", headers.get("server", "")) or \
            re.search(r"/\d", headers.get("x-powered-by", "")):
        findings.append(ctx.finding(
            "http-version-disclosure", "El servidor web revela su versión", "LOW",
            "El servidor muestra qué programa y qué versión usa. Un atacante puede buscar fallos conocidos de esa versión.",
            "Oculta la versión en la configuración (por ejemplo 'server_tokens off' en nginx o 'ServerTokens Prod' en Apache).",
            "; ".join(shown)))
    return ScriptOutput("\n".join(shown), findings) if shown else None


@script("http-methods", "default,safe", "Métodos HTTP que anuncia el servidor (OPTIONS)", services="http")
async def http_methods(ctx: ScriptContext):
    res = await http_fetch(ctx, "OPTIONS")
    if not res or "allow" not in res[1]:
        return None
    allow = res[1]["allow"]
    methods = {m.strip().upper() for m in allow.split(",")}
    findings = []
    risky = sorted(methods & {"PUT", "DELETE", "TRACE", "CONNECT"})
    if risky:
        findings.append(ctx.finding(
            "http-risky-methods", "El servidor permite métodos HTTP poco comunes", "MEDIUM" if "PUT" in risky or "DELETE" in risky else "LOW",
            "Métodos como PUT o DELETE pueden permitir subir o borrar archivos y TRACE ayuda a robar datos en ciertos ataques.",
            "Desactiva los métodos que la aplicación no necesita y deja solo GET, HEAD y POST.", f"Allow: {allow}"))
    return ScriptOutput(f"Allow: {allow}", findings)


def _name_value(rdns, key: str) -> str:
    for rdn in rdns or ():
        for k, v in rdn:
            if k == key:
                return v
    return ""


@script("ssl-cert", "default,safe", "Datos del certificado TLS (quién lo emitió, cuándo vence)", services="https,ssl")
async def ssl_cert(ctx: ScriptContext):
    got = await netio.fetch_cert(ctx.host, ctx.port, ctx.timeout, ctx.hostname or None)
    if not got:
        return None
    der, version, cipher = got
    info = netio.decode_cert(der)
    lines = [f"Protocolo negociado: {version}  Cifrado: {cipher}", f"Huella SHA-256: {netio.cert_fingerprint(der)}"]
    findings: list[Finding] = []
    if info:
        subject, issuer = netio.cert_name(info.get("subject")), netio.cert_name(info.get("issuer"))
        sans = [v for k, v in info.get("subjectAltName", ()) if k == "DNS"]
        lines[:0] = [f"Sujeto: {subject}", f"Emisor: {issuer}",
                     f"Válido: {info.get('notBefore', '?')} hasta {info.get('notAfter', '?')}"]
        if sans:
            lines.append("Nombres alternativos: " + ", ".join(sans[:8]) + (" ..." if len(sans) > 8 else ""))
        end = netio.parse_cert_date(info.get("notAfter", ""))
        if end:
            days = (end - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(ctx.finding(
                    "cert-expired", "El certificado TLS está vencido", "HIGH",
                    "Los navegadores muestran una advertencia de seguridad y la conexión ya no es confiable.",
                    "Renueva el certificado (con Let's Encrypt es gratis y automático).", f"Venció hace {-days} días"))
            elif days <= 15:
                findings.append(ctx.finding(
                    "cert-expiring", "El certificado TLS vence pronto", "LOW",
                    "Si no se renueva a tiempo, el sitio dejará de ser confiable para los visitantes.",
                    "Renueva el certificado y activa la renovación automática.", f"Vence en {days} días"))
        if subject and subject == issuer:
            findings.append(ctx.finding(
                "cert-self-signed", "El certificado TLS es autofirmado", "LOW",
                "Nadie externo garantiza la identidad del servidor, así que los navegadores avisan de un posible riesgo.",
                "Si el servicio es público, usa un certificado de una autoridad reconocida (Let's Encrypt es gratis).",
                f"Sujeto y emisor: {subject}"))
    return ScriptOutput("\n".join(lines), findings)


@script("ssl-weak-protocols", "vuln,safe", "Revisa si el servidor acepta versiones antiguas de TLS (1.0 y 1.1)",
        services="https,ssl")
async def ssl_weak_protocols(ctx: ScriptContext):
    import ssl as _ssl
    results = {}
    for label, ver in (("TLSv1.0", _ssl.TLSVersion.TLSv1), ("TLSv1.1", _ssl.TLSVersion.TLSv1_1),
                       ("TLSv1.2", _ssl.TLSVersion.TLSv1_2), ("TLSv1.3", _ssl.TLSVersion.TLSv1_3)):
        try:
            context = netio.tls_context(min_version=ver, max_version=ver)
            _r, w = await netio.open_stream(ctx.host, ctx.port, ctx.timeout, tls=context,
                                            server_hostname=ctx.hostname or None)
            await netio.close_stream(w)
            results[label] = True
        except (netio.CONNECT_ERRORS + (ValueError,)):
            results[label] = False
    text = "; ".join(f"{k}: {'aceptado' if v else 'no aceptado'}" for k, v in results.items())
    findings = []
    old = [k for k in ("TLSv1.0", "TLSv1.1") if results.get(k)]
    if old:
        findings.append(ctx.finding(
            "tls-old-protocols", "El servidor acepta versiones antiguas de TLS", "MEDIUM",
            "TLS 1.0 y 1.1 tienen debilidades conocidas y los navegadores modernos ya no los usan.",
            "Deja habilitados solo TLS 1.2 y TLS 1.3 en el servidor web o balanceador.", ", ".join(old),
            "https://datatracker.ietf.org/doc/html/rfc8996"))
    text += "  (si tu Python local no permite probar TLS 1.0/1.1, aparecerán como 'no aceptado')"
    return ScriptOutput(text, findings)


@script("ssh-protocol", "default,safe", "Versión del protocolo SSH y señales de software antiguo", services="ssh")
async def ssh_protocol(ctx: ScriptContext):
    m = re.match(r"SSH-(\d\.\d+)-(\S+)", ctx.banner or "")
    if not m:
        return None
    proto, soft = m.groups()
    findings = []
    if proto.startswith("1."):          # 1.x y 1.99 (acepta la versión 1)
        findings.append(ctx.finding(
            "ssh-v1", "SSH acepta el protocolo versión 1", "HIGH",
            "El protocolo SSH 1 tiene fallos de diseño conocidos que permiten espiar o alterar la conexión.",
            "Configura 'Protocol 2' (o actualiza OpenSSH, que ya no incluye la versión 1).", f"SSH-{proto}-{soft}"))
    mo = re.match(r"OpenSSH_(\d+)\.(\d+)", soft)
    if mo and (int(mo.group(1)), int(mo.group(2))) < (7, 4):
        findings.append(ctx.finding(
            "ssh-old-version", "Versión de OpenSSH muy antigua", "LOW",
            "Las versiones anteriores a la 7.4 tienen vulnerabilidades públicas y usan algoritmos débiles.",
            "Actualiza OpenSSH a una versión soportada por tu sistema operativo.", soft))
    return ScriptOutput(f"protocolo {proto}, software {soft}", findings)


@script("ftp-anon", "default,safe", "Revisa si el FTP deja entrar como 'anonymous' (sin cuenta)", services="ftp")
async def ftp_anon(ctx: ScriptContext):
    sess = await Session.open(ctx)
    try:
        greeting = await sess.recv()
        if not greeting.startswith("220"):
            return None
        reply = await sess.send("USER anonymous")
        if reply.startswith("331"):
            reply = await sess.send("PASS anonymous@example.com")
        ok = reply.startswith("230")
        await sess.send("QUIT", 1.0)
    finally:
        await sess.close()
    if not ok:
        return ScriptOutput("No permite acceso anónimo")
    return ScriptOutput("¡Acceso anónimo PERMITIDO!", [ctx.finding(
        "ftp-anonymous", "El servidor FTP permite entrar sin usuario ni contraseña", "HIGH",
        "Cualquier persona puede conectarse como 'anonymous' y ver (y a veces subir) archivos sin tener una cuenta.",
        "Desactiva el acceso anónimo en la configuración del FTP o, mejor, reemplaza FTP por SFTP.",
        "USER anonymous → 230 Login successful")])


@script("smtp-commands", "default,safe", "Comandos que anuncia el servidor de correo (EHLO)", services="smtp,submission")
async def smtp_commands(ctx: ScriptContext):
    sess = await Session.open(ctx)
    try:
        greeting = await sess.recv()
        if not greeting.startswith("220"):
            return None
        reply = await sess.send("EHLO portscanner.local")
        await sess.send("QUIT", 1.0)
    finally:
        await sess.close()
    caps = [re.sub(r"^250[- ]", "", line).strip() for line in reply.splitlines() if line.startswith("250")]
    if not caps:
        return None
    findings = []
    if not any(c.upper().startswith("STARTTLS") for c in caps) and not ctx.tls and ctx.port in (25, 587):
        findings.append(ctx.finding(
            "smtp-no-starttls", "El servidor de correo no ofrece cifrado (STARTTLS)", "LOW",
            "Sin STARTTLS los correos viajan en texto plano entre servidores y se pueden leer en el camino.",
            "Activa STARTTLS con un certificado válido en el servidor de correo.", "; ".join(caps[:8])))
    return ScriptOutput(", ".join(caps[:12]), findings)


# ---------- scripts de exposición (vuln) ----------
@script("redis-noauth", "vuln,safe", "Detecta Redis que responde sin pedir contraseña", services="redis")
async def redis_noauth(ctx: ScriptContext):
    data = await netio.exchange(ctx.host, ctx.port, b"*1\r\n$4\r\nPING\r\n", ctx.timeout, tls=ctx.tls)
    if data.startswith(b"+PONG"):
        info = await netio.exchange(ctx.host, ctx.port, b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n", ctx.timeout, tls=ctx.tls)
        ver = re.search(rb"redis_version:(\S+)", info)
        os_ = re.search(rb"os:([^\r\n]+)", info)
        extra = ", ".join(x for x in (f"versión {ver.group(1).decode()}" if ver else "",
                                      os_.group(1).decode() if os_ else "") if x)
        return ScriptOutput(f"SIN CONTRASEÑA ({extra})" if extra else "SIN CONTRASEÑA", [ctx.finding(
            "redis-noauth", "Redis abierto sin contraseña", "CRITICAL",
            "Cualquiera que llegue a este puerto puede leer, borrar o modificar todos los datos de Redis, y en muchos "
            "casos conseguir control del servidor.",
            "Activa 'requirepass' (o ACLs), limita 'bind' a 127.0.0.1 o a la red interna y bloquea el puerto 6379 en el firewall.",
            "PING → +PONG sin autenticación", "https://redis.io/docs/latest/operate/oss_and_stack/management/security/")])
    if data.startswith(b"-NOAUTH"):
        return ScriptOutput("Pide contraseña (bien)")
    return None


@script("memcached-open", "vuln,safe", "Detecta Memcached accesible sin autenticación", services="memcached")
async def memcached_open(ctx: ScriptContext):
    data = await netio.exchange(ctx.host, ctx.port, b"stats\r\n", ctx.timeout)
    if b"STAT " not in data:
        return None
    ver = re.search(rb"STAT version (\S+)", data)
    return ScriptOutput("Responde a 'stats' sin autenticación" + (f" (versión {ver.group(1).decode()})" if ver else ""),
                        [ctx.finding(
                            "memcached-open", "Memcached accesible sin autenticación", "HIGH",
                            "Cualquiera puede leer o borrar la caché y, si también responde por UDP, el servidor puede ser usado "
                            "para ataques de amplificación contra terceros.",
                            "Haz que escuche solo en 127.0.0.1 o en la red interna, desactiva UDP (-U 0) y bloquea el puerto 11211.",
                            "stats → STAT ...")])


def _bson_doc(entries: list[tuple[str, object]]) -> bytes:
    body = b""
    for key, value in entries:
        if isinstance(value, int):
            body += b"\x10" + key.encode() + b"\x00" + struct.pack("<i", value)
        else:
            raw = str(value).encode()
            body += b"\x02" + key.encode() + b"\x00" + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


@script("mongodb-noauth", "vuln,safe", "Detecta MongoDB que lista sus bases de datos sin autenticación", services="mongod,mongodb",
        ports=(27017, 27018))
async def mongodb_noauth(ctx: ScriptContext):
    doc = _bson_doc([("listDatabases", 1), ("$db", "admin")])
    payload = struct.pack("<I", 0) + b"\x00" + doc          # flagBits + sección tipo 0
    msg = struct.pack("<iiii", 16 + len(payload), 1, 0, 2013) + payload
    data = await netio.exchange(ctx.host, ctx.port, msg, ctx.timeout)
    if len(data) < 21:
        return None
    if b"totalSize" in data or b"databases" in data:
        return ScriptOutput("SIN AUTENTICACIÓN: lista las bases de datos", [ctx.finding(
            "mongodb-noauth", "MongoDB abierto sin autenticación", "CRITICAL",
            "Cualquiera que llegue a este puerto puede ver, copiar o borrar todas las bases de datos.",
            "Activa 'security.authorization: enabled', limita 'bindIp' a la red interna y bloquea el puerto 27017.",
            "listDatabases respondió sin credenciales")])
    if b"Unauthorized" in data or b"requires authentication" in data or b"not authorized" in data:
        return ScriptOutput("Exige autenticación (bien)")
    return ScriptOutput("Responde, pero no se pudo confirmar si exige autenticación")


@script("vnc-noauth", "vuln,safe", "Detecta VNC sin contraseña", services="vnc", ports=(5900, 5901, 5902))
async def vnc_noauth(ctx: ScriptContext):
    try:
        reader, writer = await netio.open_stream(ctx.host, ctx.port, ctx.timeout)
    except netio.CONNECT_ERRORS:
        return None
    try:
        hello = await netio.read_some(reader, ctx.timeout, 12, grace=0.1)
        m = re.match(rb"RFB (\d{3})\.(\d{3})", hello)
        if not m:
            return None
        major, minor = int(m.group(1)), int(m.group(2))
        writer.write(b"RFB 003.008\n" if (major, minor) >= (3, 7) else hello[:12])
        await writer.drain()
        data = await netio.read_some(reader, ctx.timeout, 64, grace=0.2)
    except netio.CONNECT_ERRORS:
        return None
    finally:
        await netio.close_stream(writer)
    if (major, minor) >= (3, 7):
        if not data or data[0] == 0:
            return ScriptOutput(f"RFB {major}.{minor}: el servidor rechazó la conexión")
        types = list(data[1:1 + data[0]])
    else:
        types = [int.from_bytes(data[:4], "big")] if len(data) >= 4 else []
    names = {1: "Ninguna", 2: "Contraseña VNC", 5: "RA2", 16: "Tight", 18: "TLS", 19: "VeNCrypt", 30: "Apple", 33: "MS-Logon"}
    text = f"RFB {major}.{minor}; autenticación: " + ", ".join(names.get(t, str(t)) for t in types)
    findings = []
    if 1 in types:
        findings.append(ctx.finding(
            "vnc-noauth", "VNC permite conectarse sin contraseña", "CRITICAL",
            "Cualquiera que llegue a este puerto puede ver y controlar el escritorio del equipo.",
            "Configura una contraseña (o mejor, usa un túnel SSH/VPN) y bloquea el puerto 5900 en el firewall.",
            "tipo de seguridad 1 (None) ofrecido"))
    return ScriptOutput(text, findings)


@script("smb-v1", "vuln,safe", "Detecta si SMB versión 1 (obsoleta y peligrosa) está activa", services="microsoft-ds,netbios-ssn",
        ports=(445, 139))
async def smb_v1(ctx: ScriptContext):
    data = await netio.exchange(ctx.host, ctx.port, SMB1_NEGOTIATE, ctx.timeout)
    if len(data) < 13:
        return ScriptOutput("SMBv1 no aceptado (el servidor cerró la conexión al negociar SMB1)")
    if data[4:8] == b"\xffSMB" and data[9:13] == b"\x00\x00\x00\x00":
        return ScriptOutput("SMBv1 HABILITADO", [ctx.finding(
            "smb-v1", "El protocolo SMB versión 1 está habilitado", "HIGH",
            "SMBv1 es obsoleto y fue la puerta de entrada de ataques masivos como WannaCry.",
            "Desactívalo (en Windows: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol') y usa SMB 2/3.",
            "El servidor aceptó el dialecto 'NT LM 0.12'", "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3")])
    if data[4:8] == b"\xfeSMB":
        return ScriptOutput("Solo SMB 2/3 (bien)")
    return ScriptOutput("SMBv1 no aceptado")


@script("docker-api-exposed", "vuln,safe", "Detecta la API de Docker accesible sin autenticación", services="docker",
        ports=(2375,))
async def docker_api(ctx: ScriptContext):
    res = await http_fetch(ctx, "GET", "/version")
    if not res or res[0] != 200 or b"ApiVersion" not in res[2]:
        return None
    ver = re.search(rb'"Version"\s*:\s*"([^"]+)"', res[2])
    return ScriptOutput("API de Docker SIN autenticación" + (f" (Docker {ver.group(1).decode()})" if ver else ""),
                        [ctx.finding(
                            "docker-api-exposed", "La API de Docker está expuesta sin autenticación", "CRITICAL",
                            "Quien llegue a este puerto puede crear contenedores y controlar por completo el servidor.",
                            "No expongas el puerto 2375. Usa el socket local o TLS con certificados de cliente (puerto 2376).",
                            "GET /version → 200 con ApiVersion")])


@script("elasticsearch-open", "vuln,safe", "Detecta Elasticsearch accesible sin autenticación", services="elasticsearch",
        ports=(9200,))
async def elasticsearch_open(ctx: ScriptContext):
    res = await http_fetch(ctx)
    if not res or res[0] != 200 or b"cluster_name" not in res[2]:
        return None
    name = re.search(rb'"cluster_name"\s*:\s*"([^"]+)"', res[2])
    return ScriptOutput("Responde sin autenticación" + (f" (cluster {name.group(1).decode()})" if name else ""),
                        [ctx.finding(
                            "elasticsearch-open", "Elasticsearch accesible sin autenticación", "HIGH",
                            "Cualquiera puede leer, modificar o borrar los índices (datos) almacenados.",
                            "Activa la seguridad integrada (usuarios y TLS), limita 'network.host' y bloquea el puerto 9200.",
                            "GET / → 200 con cluster_name")])


@script("snmp-public", "vuln,safe", "Detecta SNMP que responde a la comunidad 'public'", protocol="udp",
        services="snmp", ports=(161,))
async def snmp_public(ctx: ScriptContext):
    data = await udp_request(ctx.host, ctx.port, snmp_get_sysdescr(), ctx.timeout)
    if not data or data[:1] != b"\x30":
        return None
    m = re.search(rb"\x04([\x20-\x7e]{3,200})", data[10:])
    descr = m.group(1).decode("ascii", "replace") if m else ""
    return ScriptOutput(f"Responde a 'public': {descr}" if descr else "Responde a 'public'", [ctx.finding(
        "snmp-public", "SNMP responde a la comunidad por defecto 'public'", "MEDIUM",
        "La comunidad 'public' funciona como contraseña de lectura conocida por todos: revela el sistema, la red y "
        "a veces usuarios o configuración.",
        "Cambia la comunidad por una clave larga, migra a SNMPv3 y limita quién puede consultar el puerto 161/UDP.",
        descr or "respuesta SNMP válida")])


@script("dns-recursion", "vuln,safe", "Detecta DNS abierto que resuelve consultas de cualquiera", protocol="udp",
        services="domain", ports=(53,))
async def dns_recursion(ctx: ScriptContext):
    from . import dnsutil
    qid = 0x7273
    data = await udp_request(ctx.host, ctx.port, dnsutil.build_query("example.com", 1, qid), ctx.timeout)
    if not data or len(data) < 12:
        return None
    flags = struct.unpack("!H", data[2:4])[0]
    answers = struct.unpack("!H", data[6:8])[0]
    if flags & 0x0080 and flags & 0x000F == 0 and answers > 0:
        return ScriptOutput("Resolvedor DNS ABIERTO (resuelve para cualquiera)", [ctx.finding(
            "dns-open-resolver", "Servidor DNS abierto (resuelve consultas de cualquiera)", "MEDIUM",
            "Un resolvedor abierto puede usarse para ataques de amplificación contra terceros y para espiar qué dominios se consultan.",
            "Limita la recursión a tus redes internas ('allow-recursion' en BIND, 'access-control' en Unbound).",
            "example.com → respuesta con recursión disponible")])
    return ScriptOutput("No resuelve consultas externas (bien)")


# ---------- selección y ejecución ----------
def list_scripts() -> list[Script]:
    return sorted(REGISTRY.values(), key=lambda s: s.name)


def select_scripts(spec: str | None, *, default: bool = False) -> list[Script]:
    """Interpreta --script: nombres y/o categorías separados por comas ('default', 'safe', 'vuln', 'all')."""
    tokens = [t.strip() for t in (spec or "").split(",") if t.strip()]
    if default and "default" not in tokens:
        tokens.append("default")
    chosen: dict[str, Script] = {}
    for token in tokens:
        if token == "all":
            chosen.update(REGISTRY)
        elif token in REGISTRY:
            chosen[token] = REGISTRY[token]
        elif any(token in s.categories for s in REGISTRY.values()):
            chosen.update({s.name: s for s in REGISTRY.values() if token in s.categories})
        else:
            raise ScriptError(f"no existe el script o categoría {token!r}. Usa 'list-scripts' para ver los disponibles.")
    return sorted(chosen.values(), key=lambda s: s.name)


async def run_script(sc: Script, ctx: ScriptContext) -> ScriptOutput | None:
    """Ejecuta un script con límite de tiempo. Las excepciones las maneja quien llama."""
    return await asyncio.wait_for(sc.run(ctx), max(ctx.timeout * 5, 10))
