"""Laboratorio de práctica: levanta servicios FALSOS y "vulnerables" en tu propio equipo (127.0.0.1).

Sirve para probar el escáner de forma segura, sin tocar equipos reales:

    # Terminal 1: levanta el laboratorio (déjalo corriendo; Ctrl+C lo detiene)
    python examples/lab_demo.py

    # Terminal 2: escanéalo
    python -m portscanner scan 127.0.0.1 -p 2121,2222,5900,6379,8080,11211 -sV --script default,vuln --i-have-authorization

Los servicios son simulaciones mínimas (no ejecutan nada real): solo responden lo justo para que los scripts del
escáner detecten "FTP anónimo", "Redis sin contraseña", "VNC sin autenticación", etc.
Escuchan únicamente en 127.0.0.1, así que no son visibles desde la red.
"""
import asyncio

HOST = "127.0.0.1"


async def ssh(reader, writer):
    writer.write(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n")        # versión antigua a propósito
    await writer.drain()


async def ftp(reader, writer):
    writer.write(b"220 (vsFTPd 3.0.3)\r\n")
    await writer.drain()
    while line := await reader.readline():
        cmd = line.decode("latin-1").strip().upper()
        if cmd.startswith("USER"):
            writer.write(b"331 Please specify the password.\r\n")
        elif cmd.startswith("PASS"):
            writer.write(b"230 Login successful.\r\n")                    # acepta a cualquiera, incluido 'anonymous'
        elif cmd.startswith("QUIT"):
            writer.write(b"221 Goodbye.\r\n")
            break
        else:
            writer.write(b"502 Command not implemented.\r\n")
        await writer.drain()


async def http(reader, writer):
    request = await reader.readuntil(b"\r\n\r\n")
    if request.startswith(b"OPTIONS"):
        head = b"HTTP/1.0 200 OK\r\nAllow: GET, POST, PUT, DELETE, TRACE\r\n\r\n"
        writer.write(head)
    else:
        body = b"<html><head><title>Panel de administracion (demo)</title></head><body>Laboratorio</body></html>"
        writer.write(b"HTTP/1.0 200 OK\r\nServer: Apache/2.2.15 (CentOS)\r\nX-Powered-By: PHP/5.3.3\r\n\r\n" + body)
    await writer.drain()


async def redis(reader, writer):
    while data := await reader.read(256):
        if b"INFO" in data:
            info = b"# Server\r\nredis_version:4.0.9\r\nos:Linux 4.4.0\r\n"
            writer.write(b"$%d\r\n" % len(info) + info + b"\r\n")
        elif b"PING" in data:
            writer.write(b"+PONG\r\n")                                    # responde sin pedir contraseña
        else:
            writer.write(b"-ERR unknown command\r\n")
        await writer.drain()


async def vnc(reader, writer):
    writer.write(b"RFB 003.008\n")
    await writer.drain()
    await reader.read(12)
    writer.write(bytes([2, 1, 2]))                                         # ofrece "ninguna" (1) y "contraseña" (2)
    await writer.drain()


async def memcached(reader, writer):
    while data := await reader.read(256):
        if b"stats" in data:
            writer.write(b"STAT pid 1\r\nSTAT version 1.4.15\r\nEND\r\n")
        elif b"version" in data:
            writer.write(b"VERSION 1.4.15\r\n")
        await writer.drain()


SERVICES = {2222: ssh, 2121: ftp, 8080: http, 6379: redis, 5900: vnc, 11211: memcached}


async def main():
    servers = []
    for port, handler in SERVICES.items():
        try:
            servers.append(await asyncio.start_server(handler, HOST, port))
        except OSError as exc:
            print(f"  ! No pude abrir el puerto {port}: {exc.strerror or exc} (¿ya está en uso?)")
    if not servers:
        return
    print(f"Laboratorio activo en {HOST}: puertos {', '.join(str(p) for p in SERVICES)}. Ctrl+C para detenerlo.")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nLaboratorio detenido.")
