"""Convierte puertos abiertos en hallazgos de seguridad (con severidad y recomendación en lenguaje simple)."""
from __future__ import annotations

import ipaddress

from .models import SEVERITY_WEIGHT, Finding, HostResult

# clave -> (severidad, título, por qué importa, cómo se arregla)
RULES: dict[str, tuple[str, str, str, str]] = {
    "telnet": ("HIGH", "Telnet está expuesto",
               "Telnet envía usuario y contraseña en texto plano: cualquiera en el camino puede leerlos.",
               "Desactiva Telnet y usa SSH. Si es un equipo de red antiguo, limita el acceso a una red de administración."),
    "ftp": ("MEDIUM", "FTP está expuesto",
            "FTP envía las contraseñas y los archivos sin cifrar, y suele estar mal configurado.",
            "Reemplázalo por SFTP/FTPS. Si debe seguir activo, exige FTPS y limita las IP que pueden conectarse."),
    "tftp": ("MEDIUM", "TFTP está expuesto",
             "TFTP no tiene contraseñas: quien llegue al puerto puede pedir (y a veces subir) archivos.",
             "Desactívalo si no lo usas y limítalo a la red de administración."),
    "smb": ("HIGH", "SMB (archivos compartidos de Windows) está expuesto",
            "El puerto 445 es el más atacado en redes Windows: fue la entrada de ransomware como WannaCry.",
            "Bloquea el puerto 445 en el firewall hacia internet, mantén Windows actualizado y desactiva SMBv1."),
    "netbios": ("MEDIUM", "NetBIOS está expuesto",
                "NetBIOS revela nombres de equipos, usuarios y recursos compartidos de la red.",
                "Desactiva NetBIOS sobre TCP/IP si no lo necesitas y bloquea los puertos 137-139."),
    "msrpc": ("MEDIUM", "RPC de Windows está expuesto",
              "El puerto 135 permite consultar servicios internos de Windows y ha tenido fallos graves.",
              "Bloquéalo en el firewall: no debe ser accesible desde fuera de la red interna."),
    "rdp": ("HIGH", "Escritorio remoto (RDP) está expuesto",
            "RDP expuesto a internet recibe ataques de fuerza bruta constantes y ha tenido fallos críticos (BlueKeep).",
            "No lo expongas: usa VPN o un acceso con autenticación de múltiples factores, y activa NLA."),
    "vnc": ("HIGH", "VNC está expuesto",
            "VNC suele usar contraseñas débiles y poco cifrado; da control total del escritorio.",
            "Ponlo detrás de una VPN o túnel SSH y usa contraseñas largas."),
    "mysql": ("HIGH", "Base de datos MySQL/MariaDB expuesta",
              "Una base de datos accesible desde la red recibe ataques de contraseñas y fallos conocidos.",
              "Haz que escuche solo en 127.0.0.1 o en la red privada (bind-address) y bloquea el puerto 3306."),
    "postgresql": ("HIGH", "Base de datos PostgreSQL expuesta",
                   "Una base de datos accesible desde la red recibe ataques de contraseñas y fallos conocidos.",
                   "Limita 'listen_addresses' y pg_hba.conf a las redes necesarias y bloquea el puerto 5432."),
    "mssql": ("HIGH", "Base de datos Microsoft SQL Server expuesta",
              "SQL Server expuesto es objetivo habitual de ataques de contraseñas ('sa') y ransomware.",
              "Bloquea el puerto 1433 hacia internet y usa VPN o red privada."),
    "oracle": ("HIGH", "Base de datos Oracle expuesta",
               "El listener de Oracle expuesto permite descubrir y atacar la base de datos.",
               "Limita el acceso al listener a las IP de las aplicaciones."),
    "mongodb": ("HIGH", "Base de datos MongoDB expuesta",
                "Muchas filtraciones masivas de datos vinieron de MongoDB abiertas a internet.",
                "Activa autenticación, limita 'bindIp' y bloquea el puerto 27017."),
    "redis": ("HIGH", "Redis está expuesto",
              "Redis no está pensado para internet: sin contraseña permite leer, borrar y a veces tomar el servidor.",
              "Limita 'bind' a 127.0.0.1, activa 'requirepass' y bloquea el puerto 6379."),
    "memcached": ("HIGH", "Memcached está expuesto",
                  "Memcached no tiene autenticación y se usa en ataques de amplificación.",
                  "Haz que escuche solo en 127.0.0.1 y desactiva UDP."),
    "elasticsearch": ("HIGH", "Elasticsearch está expuesto",
                      "Los datos de Elasticsearch abierto han sido robados o borrados en muchos incidentes.",
                      "Activa la seguridad integrada y limita el acceso al puerto 9200."),
    "couchdb": ("MEDIUM", "CouchDB está expuesto",
                "Una base de datos accesible desde la red es un objetivo directo.",
                "Limita el acceso por firewall y exige usuarios y contraseñas."),
    "cassandra": ("MEDIUM", "Cassandra está expuesta", "Una base de datos accesible desde la red es un objetivo directo.",
                  "Limita el acceso por firewall y activa autenticación."),
    "zookeeper": ("MEDIUM", "ZooKeeper está expuesto", "ZooKeeper no debería ser accesible desde fuera del clúster.",
                  "Limita el acceso por firewall a los nodos del clúster."),
    "docker": ("CRITICAL", "La API de Docker está expuesta",
               "Quien llegue al puerto 2375 puede crear contenedores y tomar el control total del servidor.",
               "Cierra el puerto 2375. Si necesitas acceso remoto, usa TLS con certificados de cliente (2376) o SSH."),
    "kubernetes": ("MEDIUM", "API de Kubernetes expuesta",
                   "La API de Kubernetes accesible desde internet es un objetivo frecuente.",
                   "Limita el acceso a redes de administración y exige autenticación fuerte."),
    "kubelet": ("HIGH", "Kubelet expuesto", "El kubelet permite ejecutar comandos en los contenedores si no está protegido.",
                "Cierra los puertos 10250/10255 hacia fuera del clúster y desactiva el acceso anónimo."),
    "etcd": ("HIGH", "etcd está expuesto", "etcd guarda los secretos de Kubernetes y no debería ser accesible desde la red.",
             "Limita el acceso a los nodos de control y exige certificados de cliente."),
    "snmp": ("MEDIUM", "SNMP está expuesto",
             "SNMP con comunidades por defecto revela información detallada de la red y los equipos.",
             "Usa SNMPv3, cambia las comunidades por defecto y limita quién puede consultar."),
    "rpcbind": ("MEDIUM", "rpcbind (portmapper) está expuesto",
                "Revela qué servicios RPC/NFS hay en el equipo y se usa en ataques de amplificación.",
                "Bloquea el puerto 111 hacia fuera de la red interna."),
    "nfs": ("HIGH", "NFS está expuesto", "NFS mal configurado permite montar y leer carpetas del servidor.",
            "Limita las IP permitidas en /etc/exports y bloquea el puerto 2049 hacia internet."),
    "rsync": ("MEDIUM", "rsync está expuesto", "Un servidor rsync sin autenticación permite listar y descargar archivos.",
              "Exige usuarios/contraseña y limita las IP permitidas, o usa rsync sobre SSH."),
    "x11": ("HIGH", "X11 está expuesto", "Un servidor X11 abierto permite ver la pantalla y capturar teclado.",
            "Desactiva la escucha por red de X11 y usa SSH con reenvío (-X)."),
    "wsman": ("MEDIUM", "Administración remota de Windows (WinRM) expuesta",
              "WinRM permite ejecutar comandos en el equipo si se consiguen credenciales.",
              "Limítalo a redes de administración o VPN y exige autenticación fuerte."),
    "ajp": ("HIGH", "Conector AJP de Tomcat expuesto",
            "AJP expuesto ha permitido leer archivos y ejecutar código en Tomcat (fallo 'Ghostcat').",
            "Desactiva el conector AJP o limítalo a 127.0.0.1 y exige 'secret'."),
    "upnp": ("MEDIUM", "UPnP está expuesto", "UPnP permite abrir puertos en el router sin autenticación.",
             "Desactiva UPnP en el router y no lo expongas a internet."),
    "ipp": ("LOW", "Servicio de impresión (IPP/CUPS) expuesto", "Los servicios de impresión han tenido fallos que permiten ejecutar código.",
            "Limita el acceso a la red local y mantén CUPS actualizado."),
    "jetdirect": ("LOW", "Puerto de impresión directa expuesto", "Permite enviar trabajos a la impresora sin autenticación.",
                  "Limita el acceso a la red local."),
    "radmin": ("HIGH", "Radmin está expuesto", "Es una herramienta de control remoto que da acceso total al equipo.",
               "Limítalo a VPN y usa contraseñas largas."),
    "ldap": ("MEDIUM", "LDAP sin cifrar está expuesto", "LDAP (389) envía consultas sin cifrar y puede revelar usuarios del directorio.",
             "Usa LDAPS (636) o StartTLS y limita el acceso a las aplicaciones que lo necesitan."),
    "smtp": ("LOW", "Servidor de correo (SMTP) expuesto", "Un servidor SMTP mal configurado puede usarse para enviar spam.",
             "Verifica que no sea 'open relay' y que exija autenticación para enviar."),
    "mqtt": ("MEDIUM", "MQTT está expuesto", "Un broker MQTT sin autenticación deja leer y enviar mensajes de dispositivos.",
             "Exige usuario/contraseña y TLS, y limita el acceso por firewall."),
}

ALIASES = {
    "telnet": "telnet", "ftp": "ftp", "ftp-data": "ftp", "tftp": "tftp", "microsoft-ds": "smb", "smb": "smb",
    "netbios-ssn": "netbios", "netbios-ns": "netbios", "netbios-dgm": "netbios", "msrpc": "msrpc",
    "ms-wbt-server": "rdp", "rdp": "rdp", "vnc": "vnc", "vnc-1": "vnc", "vnc-http": "vnc", "mysql": "mysql", "mysqlx": "mysql",
    "postgresql": "postgresql", "ms-sql-s": "mssql", "ms-sql-m": "mssql", "oracle": "oracle", "mongod": "mongodb",
    "mongodb": "mongodb", "redis": "redis", "memcached": "memcached", "elasticsearch": "elasticsearch",
    "elasticsearch-nodes": "elasticsearch", "couchdb": "couchdb", "cassandra": "cassandra", "zookeeper": "zookeeper",
    "docker": "docker", "docker-ssl": "docker", "kubernetes-api": "kubernetes", "kubelet": "kubelet", "kubelet-ro": "kubelet",
    "etcd-client": "etcd", "etcd-server": "etcd", "snmp": "snmp", "rpcbind": "rpcbind", "nfs": "nfs", "rsync": "rsync",
    "x11": "x11", "x11:1": "x11", "wsman": "wsman", "wsmans": "wsman", "ajp13": "ajp", "upnp": "upnp", "ipp": "ipp",
    "jetdirect": "jetdirect", "radmin": "radmin", "ldap": "ldap", "smtp": "smtp", "mqtt": "mqtt",
}
# El servicio "docker" por número (2375) no debe confundirse si ya se confirmó como HTTP genérico
DOCKER_TLS = {"docker-ssl"}

MANY_OPEN = 20


def _canon(service: str) -> str | None:
    base = service.split("/")[-1].rstrip("?").lower()
    return ALIASES.get(base)


def build_findings(hosts: list[HostResult], script_findings: list[Finding]) -> list[Finding]:
    """Hallazgos por servicios expuestos, más un inventario por equipo. Evita repetir lo que ya dijo un script."""
    findings: list[Finding] = []
    by_port: dict[tuple[str, int, str], int] = {}
    for f in script_findings:
        if f.port is not None:
            key = (f.host, f.port, f.protocol or "tcp")
            by_port[key] = max(by_port.get(key, 0), SEVERITY_WEIGHT.get(f.severity, 0))

    for host in hosts:
        open_ports = [p for p in host.ports if p.state == "open"]
        loopback = ipaddress.ip_address(host.address).is_loopback
        for p in open_ports:
            key = _canon(p.service)
            if loopback:
                continue      # en localhost no se puede saber si el servicio es visible desde la red
            if key == "docker" and p.service == "docker-ssl":
                continue
            if key is None:
                continue
            severity, title, why, fix = RULES[key]
            if by_port.get((host.address, p.port, p.protocol), -1) >= SEVERITY_WEIGHT[severity]:
                continue       # un script ya reportó algo igual o más grave en este puerto
            where = f"{host.address}:{p.port}/{p.protocol}"
            desc = f"{why} (Detectado en {where}"
            desc += f", servicio {p.service}" + (f" {p.version_text}" if p.version_text else "") + ")."
            if not p.confirmed:
                desc += " El servicio se infirió por el número de puerto y no se pudo confirmar."
            findings.append(Finding(f"ports.{key}", f"{title} ({where})", severity, desc, fix,
                                    f"{where} {p.service} {p.version_text}".strip(),
                                    host=host.address, port=p.port, protocol=p.protocol))
        if len(open_ports) > MANY_OPEN:
            findings.append(Finding(
                "ports.many-open", f"Muchos puertos abiertos en {host.address} ({len(open_ports)})", "MEDIUM",
                f"El equipo {host.address} tiene {len(open_ports)} puertos abiertos. Cada puerto abierto es una puerta más que defender.",
                "Cierra los servicios que no necesites y filtra el resto con un firewall.",
                ", ".join(str(p.port) for p in open_ports[:60]), host=host.address))
        if host.up:
            listing = ", ".join(f"{p.port}/{p.protocol} {p.service}" for p in open_ports) or "ninguno"
            findings.append(Finding(
                "ports.inventory", f"Puertos abiertos en {host.address}" + (f" ({host.hostname})" if host.hostname else ""),
                "INFO", f"Puertos abiertos encontrados: {listing}.",
                "Revisa que cada servicio abierto sea necesario y esté actualizado.", listing, host=host.address))
    findings.extend(script_findings)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.host, f.port or 0))
    return findings
