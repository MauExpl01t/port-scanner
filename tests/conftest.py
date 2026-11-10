"""Servidores falsos en 127.0.0.1 para probar sin depender de internet ni de equipos reales."""
from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading

import pytest


class FakeTcpServer:
    """Servidor TCP en un hilo. `handler(conn)` decide qué hacer con cada conexión."""

    def __init__(self, handler, tls_context: ssl.SSLContext | None = None):
        self.handler = handler
        self.tls_context = tls_context
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(50)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(3)
            if self.tls_context:
                conn = self.tls_context.wrap_socket(conn, server_side=True)
            self.handler(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def tcp_server():
    servers = []

    def make(handler, tls_context=None):
        s = FakeTcpServer(handler, tls_context)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


@pytest.fixture
def closed_port():
    """Un puerto en el que nadie escucha (se reserva un instante y se libera)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def tls_context_pair(tmp_path_factory):
    """Certificado autofirmado de prueba generado con openssl (se salta si openssl no existe)."""
    exe = shutil.which("openssl")
    if not exe:
        pytest.skip("openssl no está instalado")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "30", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def read_until(conn, marker: bytes = b"\r\n", limit: int = 4096) -> bytes:
    data = b""
    while marker not in data and len(data) < limit:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
    return data
