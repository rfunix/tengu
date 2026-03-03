"""Shared Pydantic models for Tengu."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# ============================================================
# SCAN MODELS
# ============================================================


class Port(BaseModel):
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    version: str | None = None
    banner: str | None = None


class Host(BaseModel):
    address: str
    hostname: str | None = None
    os: str | None = None
    ports: list[Port] = []
    status: str = "up"


class ScanResult(BaseModel):
    tool: str
    target: str
    command: list[str]
    hosts: list[Host] = []
    raw_output: str = ""
    duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None


class SubdomainResult(BaseModel):
    domain: str
    subdomains: list[str] = []
    tool: str = "subfinder"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DNSRecord(BaseModel):
    name: str
    record_type: str
    value: str
    ttl: int | None = None


class DNSResult(BaseModel):
    domain: str
    records: list[DNSRecord] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class WhoisResult(BaseModel):
    target: str
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    name_servers: list[str] = []
    status: list[str] = []
    emails: list[str] = []
    org: str | None = None
    country: str | None = None
    raw: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# WEB MODELS
# ============================================================


class SecurityHeader(BaseModel):
    name: str
    value: str | None = None
    present: bool = False
    score: Literal["pass", "warn", "fail"] = "fail"
    recommendation: str | None = None


class HeaderAnalysisResult(BaseModel):
    url: str
    headers: list[SecurityHeader] = []
    score: int = 0  # 0-100
    grade: str = "F"  # A+, A, B, C, D, F
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class CORSResult(BaseModel):
    url: str
    vulnerable: bool = False
    issues: list[str] = []
    allow_origin: str | None = None
    allow_credentials: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SSLResult(BaseModel):
    host: str
    port: int = 443
    certificate_valid: bool = False
    certificate_expiry: str | None = None
    protocols: list[str] = []
    weak_protocols: list[str] = []
    cipher_suites: list[str] = []
    vulnerabilities: list[str] = []
    grade: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# FINDING MODELS
# ============================================================


class Evidence(BaseModel):
    type: Literal["http_request", "http_response", "screenshot", "tool_output", "code_snippet"]
    title: str
    content: str  # Text or base64 for images


class Finding(BaseModel):
    id: str  # TENGU-2026-001
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: object) -> object:
        if isinstance(v, str) and v.lower() == "informational":
            return "info"
        return v
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: int | None = None
    cwe_name: str | None = None
    owasp_category: str | None = None
    cve_ids: list[str] = []
    affected_asset: str
    description: str
    impact: str = ""
    steps_to_reproduce: list[str] = []
    evidence: list[Evidence] = []
    remediation_short: str = ""
    remediation_long: str = ""
    references: list[str] = []
    status: Literal["open", "remediated", "accepted_risk"] = "open"
    tool: str = ""
    raw_output: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# REPORTING MODELS
# ============================================================


class ToolInfo(BaseModel):
    name: str
    version: str | None = None
    path: str | None = None
    available: bool = False


class RiskMatrix(BaseModel):
    """5x5 risk matrix (Likelihood x Impact)."""

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total: int = 0
    risk_score: float = 0.0


class PentestReport(BaseModel):
    client_name: str
    engagement_type: Literal["blackbox", "greybox", "whitebox"]
    scope: list[str]
    exclusions: list[str] = []
    engagement_dates: str
    methodology: str = "PTES"
    tools_used: list[ToolInfo] = []
    findings: list[Finding] = []
    overall_risk_score: float = 0.0
    executive_summary: str | None = None
    conclusion: str | None = None
    risk_matrix: RiskMatrix | None = None
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# CVE MODELS
# ============================================================


class CVSSMetrics(BaseModel):
    version: str  # "3.1" or "4.0"
    vector_string: str
    base_score: float
    severity: str
    exploitability_score: float | None = None
    impact_score: float | None = None


class CVERecord(BaseModel):
    id: str  # CVE-2024-1234
    description: str
    published: str
    last_modified: str
    cvss: list[CVSSMetrics] = []
    cwe_ids: list[str] = []
    references: list[str] = []
    affected_products: list[str] = []
    exploit_available: bool = False
    metasploit_module: str | None = None


# ============================================================
# TOOL STATUS MODELS
# ============================================================


class ToolStatus(BaseModel):
    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    category: str = "unknown"


class ToolsCheckResult(BaseModel):
    tools: list[ToolStatus] = []
    total: int = 0
    available: int = 0
    missing: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# STEALTH MODELS
# ============================================================


class StealthStatus(BaseModel):
    enabled: bool
    proxy_active: bool
    proxy_url: str | None = None
    tor_connected: bool = False
    exit_node_ip: str | None = None
    exit_node_country: str | None = None
    wrapper_mode: str = "none"
    user_agent_rotation: bool = False
    current_user_agent: str | None = None
    dns_privacy: str = "system"
    timing_jitter: bool = False


class AnonymityCheckResult(BaseModel):
    real_ip_exposed: bool
    detected_ip: str
    tor_exit_node: bool = False
    dns_leak_detected: bool = False
    dns_servers_detected: list[str] = []
    anonymity_level: Literal["none", "low", "medium", "high"] = "none"
    recommendations: list[str] = []


class ProxyCheckResult(BaseModel):
    proxy_url: str
    reachable: bool
    latency_ms: float | None = None
    exit_ip: str | None = None
    anonymity_level: Literal["transparent", "anonymous", "elite"] | None = None
    supports_https: bool = False
    country: str | None = None


# ============================================================
# OSINT MODELS
# ============================================================


class OSINTResult(BaseModel):
    target: str
    tool: str
    emails: list[str] = []
    subdomains: list[str] = []
    ips: list[str] = []
    technologies: list[str] = []
    hosts: list[str] = []
    raw_output: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SecretFinding(BaseModel):
    detector: str
    verified: bool = False
    source_file: str = ""
    commit: str | None = None
    description: str = ""
    raw: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ContainerVulnerability(BaseModel):
    vuln_id: str
    pkg_name: str
    installed_version: str = ""
    fixed_version: str | None = None
    severity: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    description: str = ""
    cvss_score: float | None = None


class CloudFinding(BaseModel):
    service: str
    region: str = ""
    resource_id: str = ""
    rule_id: str = ""
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    compliance: list[str] = []
    description: str = ""
    remediation: str = ""


class ADEnumResult(BaseModel):
    target: str
    domain: str = ""
    users: list[str] = []
    groups: list[str] = []
    shares: list[str] = []
    policies: list[str] = []
    kerberos_tickets: list[str] = []
    tool: str = ""
    raw_output: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
