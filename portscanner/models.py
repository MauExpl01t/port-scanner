"""Estructuras de datos del escaneo."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_WEIGHT = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 7, "LOW": 2, "INFO": 0}

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
OPEN_FILTERED = "open|filtered"


@dataclass
class ScriptResult:
    name: str
    output: str


@dataclass
class Finding:
    check: str
    title: str
    severity: str
    description: str
    recommendation: str = ""
    evidence: str = ""
    reference: str = ""
    host: str = ""
    port: int | None = None
    protocol: str = ""

    def to_dict(self) -> dict:
        data = {
            "check": self.check, "title": self.title, "severity": self.severity,
            "description": self.description, "recommendation": self.recommendation,
            "evidence": self.evidence, "reference": self.reference,
        }
        if self.host:
            data["host"] = self.host
        if self.port is not None:
            data["port"] = self.port
            data["protocol"] = self.protocol or "tcp"
        return data


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = CLOSED
    reason: str = ""
    service: str = "unknown"
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tls: bool = False
    confirmed: bool = False          # True si el servicio se comprobó (no solo se adivinó por el número)
    banner: str = ""
    scripts: list[ScriptResult] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state == OPEN

    @property
    def version_text(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        text = " ".join(parts)
        if self.extrainfo:
            text = f"{text} ({self.extrainfo})" if text else f"({self.extrainfo})"
        return text

    def to_dict(self) -> dict:
        return {
            "port": self.port, "protocol": self.protocol, "state": self.state, "reason": self.reason,
            "service": self.service, "product": self.product, "version": self.version,
            "extrainfo": self.extrainfo, "tls": self.tls, "confirmed": self.confirmed,
            "banner": self.banner,
            "scripts": [{"name": s.name, "output": s.output} for s in self.scripts],
        }


@dataclass
class OSGuess:
    family: str
    detail: str = ""
    confidence: str = "baja"        # baja | media | alta
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"family": self.family, "detail": self.detail, "confidence": self.confidence,
                "reasons": list(self.reasons)}

    def __str__(self) -> str:
        text = self.family
        if self.detail:
            text += f" ({self.detail})"
        return f"{text} — confianza {self.confidence}"


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    up: bool = True
    reason: str = ""
    latency_ms: float | None = None
    ttl: int | None = None
    mac: str = ""
    ports: list[PortResult] = field(default_factory=list)
    os_guess: OSGuess | None = None
    traceroute: list[dict] = field(default_factory=list)
    scripts: list[ScriptResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == OPEN]

    def count(self, state: str) -> int:
        return sum(1 for p in self.ports if p.state == state)

    def to_dict(self) -> dict:
        return {
            "address": self.address, "hostname": self.hostname, "up": self.up, "reason": self.reason,
            "latency_ms": self.latency_ms, "ttl": self.ttl, "mac": self.mac,
            "os": self.os_guess.to_dict() if self.os_guess else None,
            "ports": [p.to_dict() for p in self.ports],
            "traceroute": self.traceroute, "notes": list(self.notes),
        }


@dataclass
class ScanResult:
    targets: list[str]
    started_at: str
    finished_at: str = ""
    hosts: list[HostResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    interrupted: bool = False
    hosts_total: int = 0
    command: str = ""

    @property
    def hosts_up(self) -> int:
        return sum(1 for h in self.hosts if h.up)


def compute_score(findings: list[Finding]) -> int:
    score = 100 - sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(0, min(100, score))
