"""Listas de puertos, nombres de servicios y lectura de la opción -p."""
from __future__ import annotations

import random

MAX_PORT = 65535

# Los 100 puertos TCP más comunes, de más a menos frecuentes.
TOP_TCP = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000,
    32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081,
    2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144,
    7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646,
    49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
]

# Puertos importantes que no están entre los 100 primeros (bases de datos, contenedores, remoto...).
EXTRA_TCP = [
    161, 162, 5432, 1521, 1434, 2375, 2376, 2181, 4444, 5353, 5601, 5672, 5984, 5985, 5986, 6379, 7001,
    8086, 8200, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 11211, 15672, 27017, 27018, 50000, 61616,
    69, 123, 137, 138, 161, 389, 636, 902, 1194, 1883, 2082, 2083, 2087, 3260, 3690, 4443, 4848, 5222,
    5555, 5938, 6667, 7547, 8083, 8088, 8140, 8161, 8291, 8443, 8880, 9001, 9418, 10250, 10255, 16992,
    20000, 33060, 37777, 44818, 47808, 49000, 55553, 6443, 2379, 2380, 4369, 5000, 5900, 5901, 5938,
]

TOP_UDP = [
    53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353,
    49152, 5060, 11211, 1701, 1194, 389, 111, 177, 623, 2049, 5683, 3478, 10080, 47808, 44818, 1812, 1813,
    554, 5355, 5432, 9999, 19132, 27015, 17185, 3702, 3283, 2427, 1645, 1646, 1604, 7777, 8767, 30718,
]

TCP_SERVICES = {
    1: "tcpmux", 7: "echo", 9: "discard", 13: "daytime", 17: "qotd", 19: "chargen", 20: "ftp-data",
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 26: "rsftp", 37: "time", 42: "nameserver",
    43: "whois", 49: "tacacs", 53: "domain", 70: "gopher", 79: "finger", 80: "http", 81: "hosts2-ns",
    88: "kerberos-sec", 102: "iso-tsap", 106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 144: "news", 161: "snmp", 162: "snmptrap", 179: "bgp", 199: "smux", 389: "ldap",
    427: "svrloc", 443: "https", 444: "snpp", 445: "microsoft-ds", 464: "kpasswd5", 465: "smtps",
    500: "isakmp", 512: "exec", 513: "login", 514: "shell", 515: "printer", 520: "route", 543: "klogin",
    544: "kshell", 548: "afp", 554: "rtsp", 587: "submission", 593: "http-rpc-epmap", 631: "ipp",
    636: "ldapssl", 646: "ldp", 691: "msexch-routing", 873: "rsync", 902: "vmware-auth", 990: "ftps",
    993: "imaps", 995: "pop3s", 1025: "NFS-or-IIS", 1026: "LSA-or-nterm", 1027: "IIS", 1028: "unknown",
    1029: "ms-lsa", 1080: "socks", 1110: "nfsd-status", 1194: "openvpn", 1433: "ms-sql-s",
    1434: "ms-sql-m", 1521: "oracle", 1604: "citrix-ica", 1720: "h323q931", 1723: "pptp", 1755: "wms",
    1883: "mqtt", 1900: "upnp", 2000: "cisco-sccp", 2001: "dc", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2087: "whm-ssl", 2121: "ccproxy-ftp", 2181: "zookeeper", 2375: "docker",
    2376: "docker-ssl", 2379: "etcd-client", 2380: "etcd-server", 2717: "pn-requester", 3000: "ppp",
    3128: "squid-http", 3260: "iscsi", 3306: "mysql", 3389: "ms-wbt-server", 3690: "svn",
    3986: "mapper-ws-ethd", 4369: "epmd", 4443: "pharos", 4444: "krb524", 4848: "appserv-http",
    4899: "radmin", 5000: "upnp", 5009: "airport-admin", 5051: "ida-agent", 5060: "sip", 5101: "admdog",
    5190: "aol", 5222: "xmpp-client", 5357: "wsdapi", 5432: "postgresql", 5555: "freeciv",
    5601: "kibana", 5631: "pcanywheredata", 5666: "nrpe", 5672: "amqp", 5800: "vnc-http", 5900: "vnc",
    5901: "vnc-1", 5938: "teamviewer", 5984: "couchdb", 5985: "wsman", 5986: "wsmans", 6000: "X11",
    6001: "X11:1", 6379: "redis", 6443: "kubernetes-api", 6646: "unknown", 6667: "irc", 7001: "afs3-callback",
    7070: "realserver", 7547: "cwmp", 8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
    8081: "blackice-icecap", 8083: "us-srv", 8086: "influxdb", 8088: "radan-http", 8140: "puppet",
    8161: "activemq-web", 8200: "trivnet1", 8291: "winbox", 8443: "https-alt", 8500: "consul",
    8880: "cddbp-alt", 8888: "sun-answerbook", 9000: "cslistener", 9001: "tor-orport", 9042: "cassandra",
    9090: "zeus-admin", 9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch-nodes",
    9418: "git", 9999: "abyss", 10000: "snet-sensor-mgmt", 10250: "kubelet", 10255: "kubelet-ro",
    11211: "memcached", 15672: "rabbitmq-mgmt", 16992: "amt-soap-http", 20000: "dnp", 27017: "mongod",
    27018: "mongod", 32768: "filenet-tms", 33060: "mysqlx", 37777: "dahua-dvr", 44818: "EtherNetIP-2",
    47808: "bacnet", 49152: "unknown", 49153: "unknown", 49154: "unknown", 49155: "unknown",
    49156: "unknown", 49157: "unknown", 50000: "ibm-db2", 61616: "activemq",
}

UDP_SERVICES = {
    7: "echo", 53: "domain", 67: "dhcps", 68: "dhcpc", 69: "tftp", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 161: "snmp", 162: "snmptrap",
    177: "xdmcp", 389: "ldap", 445: "microsoft-ds", 500: "isakmp", 514: "syslog", 520: "route",
    554: "rtsp", 623: "asf-rmcp", 631: "ipp", 1194: "openvpn", 1434: "ms-sql-m", 1645: "radius",
    1646: "radacct", 1701: "l2tp", 1812: "radius", 1813: "radacct", 1900: "upnp", 2049: "nfs",
    3478: "stun", 4500: "nat-t-ike", 5060: "sip", 5353: "zeroconf", 5355: "llmnr", 5683: "coap",
    10080: "amanda", 11211: "memcached", 27015: "halflife", 44818: "EtherNetIP-2", 47808: "bacnet",
}


def service_name(port: int, protocol: str = "tcp") -> str:
    table = UDP_SERVICES if protocol == "udp" else TCP_SERVICES
    return table.get(port, "unknown")


class PortSpecError(ValueError):
    pass


def _ordered_unique(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def top_ports(n: int, protocol: str = "tcp") -> list[int]:
    """Los n puertos más comunes. Si n supera la lista curada, se completa con los números más bajos."""
    if n < 1 or n > MAX_PORT:
        raise PortSpecError(f"--top-ports debe estar entre 1 y {MAX_PORT}")
    base = TOP_UDP if protocol == "udp" else TOP_TCP + EXTRA_TCP
    ordered = _ordered_unique(base)
    if n <= len(ordered):
        return ordered[:n]
    known = set(ordered)
    ordered.extend(p for p in range(1, MAX_PORT + 1) if p not in known)
    return ordered[:n]


def _parse_token(token: str) -> list[int]:
    token = token.strip()
    if not token:
        raise PortSpecError("hay una coma de más en la lista de puertos")
    if token == "-":
        return list(range(1, MAX_PORT + 1))
    if "-" in token:
        left, _, right = token.partition("-")
        try:
            start = int(left) if left else 1
            end = int(right) if right else MAX_PORT
        except ValueError:
            raise PortSpecError(f"rango de puertos inválido: {token!r}") from None
        if start > end:
            raise PortSpecError(f"el rango {token!r} está al revés (el primero es mayor)")
    else:
        try:
            start = end = int(token)
        except ValueError:
            raise PortSpecError(f"puerto inválido: {token!r}") from None
    if start < 1 or end > MAX_PORT:
        raise PortSpecError(f"los puertos van de 1 a {MAX_PORT} (recibí {token!r})")
    return list(range(start, end + 1))


def parse_ports(spec: str, default_protocol: str = "tcp") -> tuple[list[int], list[int]]:
    """Lee la opción -p y devuelve (puertos_tcp, puertos_udp).

    Acepta: "80", "22,80,443", "1-1000", "-" (todos), "-100", "1000-", y prefijos "T:" y "U:"
    como en Nmap ("T:22,80,U:53,161"). Sin prefijo, los puertos van al protocolo por defecto.
    """
    if spec is None or not str(spec).strip():
        raise PortSpecError("la lista de puertos está vacía")
    tcp: list[int] = []
    udp: list[int] = []
    current = default_protocol
    for raw in str(spec).split(","):
        token = raw.strip()
        upper = token[:2].upper()
        if upper in ("T:", "U:"):
            current = "tcp" if upper == "T:" else "udp"
            token = token[2:]
        ports = _parse_token(token)
        (udp if current == "udp" else tcp).extend(ports)
    return sorted(set(tcp)), sorted(set(udp))


def shuffled(ports: list[int], seed: int | None = None) -> list[int]:
    """Orden aleatorio: reparte la carga y evita golpear puertos consecutivos."""
    out = list(ports)
    random.Random(seed).shuffle(out)
    return out
