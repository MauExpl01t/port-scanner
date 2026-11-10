# PortScanner — diseño

## Intención y por qué

Sexta herramienta de un portafolio de ciberseguridad en Python. El objetivo es un escáner de
puertos "tipo Nmap" **robusto**, que contemple **todos los puertos** y que escanee todo lo que sea
razonable. Sirve para aprender redes y sockets y para auditar equipos propios o con autorización
por escrito.

## Alcance (definido el 2026-11-09)

1. **Descubrir equipos** de una red (`10.10.10.0/24`), con o sin ping.
2. **Escaneo TCP**: un puerto, lista, rango, top-N, o todos (1-65535), en paralelo.
3. **Escaneo UDP** (más lento; DNS 53, SNMP 161, NTP 123...).
4. **Detección de servicios y versiones** leyendo banners y enviando sondas.
5. **Adivinar el sistema operativo** (aproximado: TTL + banners + puertos).
6. **Scripts** (chequeos opcionales: FTP anónimo, título web, certificado TLS...).
7. **Salida** en texto, JSON, XML, grepable y HTML; el JSON es compatible con `report-generator`.
8. **Opciones útiles**: plantillas de velocidad `-T0..-T5`, `-v`, `--reason`, `--traceroute`, DNS propio.

## Goals

- Solo librería estándar de Python (cero dependencias para usarlo).
- Mismo patrón de seguridad que las otras herramientas: `--i-have-authorization` obligatorio.
- Que un error de red, un Ctrl+C o un servidor raro nunca rompan el escaneo completo.
- Pruebas automáticas contra servidores falsos en `127.0.0.1`.

## Non-goals / anti-goals

- No explota vulnerabilidades ni intenta adivinar contraseñas. Los scripts solo **detectan exposición**
  (por ejemplo "Redis responde sin pedir clave"), nunca modifican nada en el objetivo.
- No intenta evadir firewalls ni IDS (sin fragmentación, sin IP falsas).
- No copia la base de huellas de Nmap: la detección de SO es aproximada y se dice.

## Decisiones de diseño

- **Escaneo principal = TCP connect** con `asyncio` (funciona sin administrador en Windows).
  `-sS` (SYN) es opcional: necesita `scapy` + Npcap + administrador; si falta, avisa y usa connect.
  El camino SYN es experimental y no está probado en este equipo.
- Descubrimiento: ping del sistema (`ping`), conexiones TCP a puertos comunes y la tabla ARP del sistema.
  No usa sockets crudos.
- Un host se considera "activo" si responde a cualquiera de esos métodos. `-Pn` se salta el descubrimiento.
- UDP: sondas específicas por protocolo; `open|filtered` cuando no hay respuesta (igual que Nmap).
- Severidad de hallazgos fija por servicio (Telnet, SMB, RDP, bases de datos expuestas...).
- Más de 256 equipos exige `--i-accept-large-scan`; más de 65 536 se rechaza siempre.
- Ctrl+C devuelve resultados parciales en vez de perderlos.
- HTML propio y autocontenido; para un informe de cliente se recomienda pasar el JSON por `report-generator`.

## Estructura

`portscanner/`: `ports.py` (listas y nombres), `targets.py`, `dnsutil.py`, `timing.py`, `discovery.py`,
`tcp.py`, `syn.py`, `udp.py`, `fingerprint.py` (servicios), `osguess.py`, `scripts.py`, `traceroute.py`,
`risk.py` (hallazgos), `scanner.py` (orquesta), `report.py`, `cli.py`.
