"""Utilidades de red compartidas por la detección de servicios y los scripts."""
from __future__ import annotations

import asyncio
import hashlib
import os
import ssl
import tempfile
import warnings
from datetime import datetime, timezone

CONNECT_ERRORS = (OSError, asyncio.TimeoutError, TimeoutError, ssl.SSLError, EOFError)


def tls_context(min_version: ssl.TLSVersion | None = None, max_version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    """Contexto TLS que acepta cualquier certificado: aquí queremos *ver* el servicio, no validarlo."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    with warnings.catch_warnings():       # TLS 1.0/1.1 están marcados como obsoletos: justo lo que queremos probar
        warnings.simplefilter("ignore", DeprecationWarning)
        if min_version is not None:
            ctx.minimum_version = min_version
        if max_version is not None:
            ctx.maximum_version = max_version
    return ctx


async def open_stream(host: str, port: int, timeout: float, *, tls: bool | ssl.SSLContext = False,
                      server_hostname: str | None = None):
    """Abre una conexión TCP (con TLS opcional). Lanza excepción si falla."""
    ctx = None
    if tls:
        ctx = tls if isinstance(tls, ssl.SSLContext) else tls_context()
    return await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=(server_hostname or None) if ctx else None,
                                ssl_handshake_timeout=timeout if ctx else None),
        timeout + (timeout if ctx else 0))


async def close_stream(writer) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except Exception:
        pass


async def read_some(reader: asyncio.StreamReader, wait: float, limit: int = 8192, grace: float = 0.25) -> bytes:
    """Lee lo que llegue: espera hasta `wait` el primer dato y luego un poco más por si vienen más trozos."""
    try:
        data = await asyncio.wait_for(reader.read(limit), wait)
    except (asyncio.TimeoutError, TimeoutError, OSError, ssl.SSLError):
        return b""
    while data and len(data) < limit:
        try:
            more = await asyncio.wait_for(reader.read(limit - len(data)), grace)
        except (asyncio.TimeoutError, TimeoutError, OSError, ssl.SSLError):
            break
        if not more:
            break
        data += more
    return data


async def exchange(host: str, port: int, payload: bytes | None, timeout: float, *, wait: float | None = None,
                   tls: bool | ssl.SSLContext = False, server_hostname: str | None = None,
                   limit: int = 8192) -> bytes:
    """Conecta, envía `payload` (si hay) y devuelve lo que responda. Nunca lanza: devuelve b'' si algo falla."""
    writer = None
    try:
        reader, writer = await open_stream(host, port, timeout, tls=tls, server_hostname=server_hostname)
        if payload:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout)
        return await read_some(reader, wait if wait is not None else timeout, limit)
    except CONNECT_ERRORS:
        return b""
    finally:
        if writer is not None:
            await close_stream(writer)


def printable(data: bytes, limit: int = 200) -> str:
    text = data[:limit].decode("latin-1")
    return "".join(c if 32 <= ord(c) < 127 else (" " if c in "\r\n\t" else ".") for c in text).strip()


def decode_cert(der: bytes) -> dict:
    """Datos legibles de un certificado (asunto, emisor, fechas...). Devuelve {} si no se puede leer."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        try:
            return ssl._ssl._test_decode_cert(path)      # función interna de Python, pero estable
        finally:
            os.unlink(path)
    except Exception:
        return {}


def cert_fingerprint(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def cert_name(rdns) -> str:
    """Convierte la estructura de nombres del certificado en texto: 'CN=ejemplo.cl, O=Mi Empresa'."""
    short = {"commonName": "CN", "organizationName": "O", "countryName": "C", "organizationalUnitName": "OU",
             "localityName": "L", "stateOrProvinceName": "ST"}
    parts = []
    for rdn in rdns or ():
        for key, value in rdn:
            parts.append(f"{short.get(key, key)}={value}")
    return ", ".join(parts)


def parse_cert_date(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


async def fetch_cert(host: str, port: int, timeout: float, server_hostname: str | None = None) -> tuple[bytes, str, str] | None:
    """Hace el saludo TLS y devuelve (certificado_DER, versión_TLS, cifrado). None si no hay TLS."""
    writer = None
    try:
        _reader, writer = await open_stream(host, port, timeout, tls=True, server_hostname=server_hostname)
        obj = writer.get_extra_info("ssl_object")
        if obj is None:
            return None
        der = obj.getpeercert(binary_form=True) or b""
        cipher = obj.cipher()
        return der, obj.version() or "", cipher[0] if cipher else ""
    except CONNECT_ERRORS:
        return None
    finally:
        if writer is not None:
            await close_stream(writer)
