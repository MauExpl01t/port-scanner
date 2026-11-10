import asyncio
import errno
import socket

import pytest

from portscanner import tcp, udp
from portscanner.models import CLOSED, FILTERED, OPEN, OPEN_FILTERED
from portscanner.timing import get_timing

FAST = get_timing(4, timeout=1.0, retries=0)


def run(coro):
    return asyncio.run(coro)


# ---------- TCP ----------
def test_tcp_abierto_y_cerrado(tcp_server, closed_port):
    srv = tcp_server(lambda conn: None)
    res = run(tcp.scan_ports("127.0.0.1", [srv.port, closed_port], FAST))
    by_port = {r.port: r for r in res}
    assert by_port[srv.port].state == OPEN
    assert by_port[closed_port].state == CLOSED
    assert by_port[closed_port].reason == "conn-refused"
    assert [r.port for r in res] == sorted([srv.port, closed_port])


def test_tcp_muchos_puertos_rapido(tcp_server):
    srv = tcp_server(lambda conn: None)
    ports = list(range(1, 2001)) + [srv.port]
    res = run(tcp.scan_ports("127.0.0.1", sorted(set(ports)), get_timing(4)))
    assert any(r.port == srv.port and r.state == OPEN for r in res)
    assert len(res) == len(set(ports))


def test_tcp_timeout_es_filtrado(monkeypatch):
    async def never(host, port, timeout):
        await asyncio.sleep(0.05)
        raise asyncio.TimeoutError()
    monkeypatch.setattr(tcp, "try_connect", never)
    res = run(tcp.scan_ports("10.255.255.1", [80], get_timing(5, timeout=0.2, retries=1)))
    assert res[0].state == FILTERED and res[0].reason == "no-response"


def test_tcp_host_inalcanzable_es_filtrado(monkeypatch):
    async def boom(host, port, timeout):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")
    monkeypatch.setattr(tcp, "try_connect", boom)
    res = run(tcp.scan_ports("10.255.255.1", [80], FAST))
    assert res[0].state == FILTERED and res[0].reason == "host-unreachable"


def test_tcp_limite_local_reintenta(monkeypatch):
    calls = {"n": 0}

    async def flaky(host, port, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise OSError(10055, "sin espacio de búfer")
    monkeypatch.setattr(tcp, "try_connect", flaky)
    res = run(tcp.scan_ports("127.0.0.1", [80], FAST))
    assert res[0].state == OPEN and calls["n"] == 3


def test_tcp_cancelacion_conserva_resultados(tcp_server, monkeypatch):
    sink = {}
    real = tcp.probe_port

    async def slow_after_first(host, port, timing, hits=None):
        if port != 1:
            await asyncio.sleep(30)
        return await real(host, port, timing, hits)
    monkeypatch.setattr(tcp, "probe_port", slow_after_first)

    async def main():
        task = asyncio.create_task(tcp.scan_ports("127.0.0.1", [1, 2, 3], FAST, sink=sink))
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    run(main())
    assert 1 in sink and 2 not in sink


def test_tcp_ipv6_loopback():
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.listen(1)
    except OSError:
        pytest.skip("este equipo no tiene IPv6")
    res = run(tcp.scan_ports("::1", [s.getsockname()[1]], FAST))
    s.close()
    assert res[0].state == OPEN


# ---------- UDP ----------
class EchoUdp:
    def __init__(self, reply=b"pong"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.reply = reply
        import threading
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                return
            if self.reply is not None:
                self.sock.sendto(self.reply, addr)

    def close(self):
        self.sock.close()


def test_udp_abierto_cerrado_y_silencioso():
    talker, silent = EchoUdp(), EchoUdp(reply=None)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    timing = get_timing(4, timeout=0.5, retries=0)
    res = {r.port: r for r in run(udp.scan_udp_ports("127.0.0.1", [talker.port, silent.port, dead], timing))}
    talker.close()
    silent.close()
    assert res[talker.port].state == OPEN and res[talker.port].reason == "udp-response"
    assert res[silent.port].state == OPEN_FILTERED
    if icmp_unreachable_works():
        assert res[dead].state == CLOSED and res[dead].reason == "port-unreach"
    else:       # algunos sistemas/firewalls no devuelven el aviso ICMP en loopback: se ve como abierto|filtrado
        assert res[dead].state in (CLOSED, OPEN_FILTERED)


def icmp_unreachable_works() -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect(("127.0.0.1", 9))
    s.send(b"x")
    try:
        s.recv(10)
    except (ConnectionError, OSError) as exc:
        return not isinstance(exc, TimeoutError)
    finally:
        s.close()
    return False


def test_udp_aviso_de_puerto_inalcanzable_es_cerrado(monkeypatch):
    class FakeProbe(udp._Probe):
        def connection_made(self, transport):
            self.transport = transport
            self._finish(("error", ConnectionResetError(10054, "reset")))
    monkeypatch.setattr(udp, "_Probe", FakeProbe)
    srv = EchoUdp()
    r = run(udp.probe_udp_port("127.0.0.1", srv.port, FAST))
    srv.close()
    assert r.state == CLOSED and r.reason == "port-unreach"


def test_udp_sonda_dns_respuesta_describe_servicio():
    svc, _, _ = udp.describe_response(53, b"\x00" * 12)
    assert svc == "domain"
    ntp = bytearray(48)
    ntp[0] = (4 << 3) | 4
    ntp[1] = 2
    svc, _, extra = udp.describe_response(123, bytes(ntp))
    assert svc == "ntp" and "v4" in extra and "stratum 2" in extra


def test_udp_snmp_paquete_bien_formado():
    pkt = udp.snmp_get_sysdescr()
    assert pkt[0] == 0x30 and pkt[1] == len(pkt) - 2
    assert b"public" in pkt and bytes([0x2B, 6, 1, 2, 1, 1, 1, 0]) in pkt


def test_udp_request_ayudante():
    srv = EchoUdp(reply=b"hola")
    assert run(udp.udp_request("127.0.0.1", srv.port, b"x", 1.0, retries=0)) == b"hola"
    srv.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    assert run(udp.udp_request("127.0.0.1", dead, b"x", 0.5, retries=0)) is None
