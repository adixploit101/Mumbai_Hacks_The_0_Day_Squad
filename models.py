"""
Data models for Security Platform
Includes models for SIEM, CTI, and Incident Response
"""
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid


# ============================================================================
# ENUMS
# ============================================================================

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class LogSource(str, Enum):
    FIREWALL = "firewall"
    SERVER = "server"
    CLOUD = "cloud"
    ENDPOINT = "endpoint"
    IDS_IPS = "ids_ips"
    APPLICATION = "application"


class IncidentType(str, Enum):
    MALWARE = "Malware"
    RANSOMWARE = "Ransomware"
    DATA_BREACH = "Data Breach"
    INSIDER_THREAT = "Insider Threat"
    PHISHING = "Phishing"
    DDOS = "DDoS"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    PRIVILEGE_ESCALATION = "Privilege Escalation"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"


class ThreatCategory(str, Enum):
    APT = "APT"
    BOTNET = "Botnet"
    PHISHING = "Phishing"
    MALWARE = "Malware"
    RANSOMWARE = "Ransomware"
    C2 = "C2"
    EXPLOIT_KIT = "Exploit Kit"
    CRYPTOMINING = "Cryptomining"


# ============================================================================
# SIEM MODELS
# ============================================================================

class LogEvent(BaseModel):
    """Normalized log entry"""
    id: str = Field(default_factory=lambda: f"log_{uuid.uuid4().hex[:12]}")
    timestamp: datetime
    source: LogSource
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    action: Optional[str] = None
    message: str
    raw_log: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Anomaly(BaseModel):
    """Detected anomaly with scoring"""
    id: str = Field(default_factory=lambda: f"anomaly_{uuid.uuid4().hex[:12]}")
    timestamp: datetime
    anomaly_type: str
    description: str
    score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    affected_entity: str
    baseline_value: Optional[float] = None
    observed_value: Optional[float] = None
    related_logs: List[str] = Field(default_factory=list)
    explanation: str


class CorrelatedEvent(BaseModel):
    """Multi-event attack chain"""
    id: str = Field(default_factory=lambda: f"corr_{uuid.uuid4().hex[:12]}")
    timestamp: datetime
    event_ids: List[str]
    attack_stage: str
    description: str
    confidence: float = Field(ge=0, le=1)
    mitre_techniques: List[str] = Field(default_factory=list)


class Alert(BaseModel):
    """Classified security alert"""
    id: str = Field(default_factory=lambda: f"alert_{uuid.uuid4().hex[:12]}")
    timestamp: datetime
    severity: Severity
    title: str
    description: str
    affected_assets: List[str] = Field(default_factory=list)
    source_events: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    confidence_score: float = Field(ge=0, le=100)
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None
    explanation: str


class Incident(BaseModel):
    """Full incident report"""
    id: str = Field(default_factory=lambda: f"incident_{uuid.uuid4().hex[:12]}")
    timestamp: datetime
    incident_type: IncidentType
    severity: Severity
    title: str
    description: str
    attack_path: List[str]
    affected_assets: List[str]
    affected_users: List[str] = Field(default_factory=list)
    impact_assessment: str
    recommended_actions: List[str]
    confidence_score: float = Field(ge=0, le=100)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    related_alerts: List[str] = Field(default_factory=list)
    explanation: str
    status: str = "open"


class BaselineProfile(BaseModel):
    """Behavioral baseline data"""
    entity_type: str
    entity_id: str
    metric: str
    baseline_value: float
    std_deviation: float
    sample_size: int
    last_updated: datetime


# ============================================================================
# CTI MODELS
# ============================================================================

class IOC(BaseModel):
    """Indicator of Compromise"""
    id: str = Field(default_factory=lambda: f"ioc_{uuid.uuid4().hex[:12]}")
    indicator: str
    ioc_type: IOCType
    first_seen: datetime
    last_seen: datetime
    source: str
    tags: List[str] = Field(default_factory=list)
    is_active: bool = True


class ThreatIntel(BaseModel):
    """Enriched threat intelligence"""
    ioc_id: str
    indicator: str
    ioc_type: IOCType
    geolocation: Optional[Dict[str, Any]] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    malware_families: List[str] = Field(default_factory=list)
    campaigns: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    threat_category: Optional[ThreatCategory] = None
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    first_seen: datetime
    last_seen: datetime
    sighting_count: int = 1
    dns_records: Optional[List[str]] = None
    whois_data: Optional[Dict[str, Any]] = None
    ssl_cert: Optional[Dict[str, Any]] = None
    enrichment_timestamp: datetime = Field(default_factory=datetime.utcnow)


class ThreatActor(BaseModel):
    """Threat actor profile"""
    id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: str
    origin_country: Optional[str] = None
    motivation: List[str] = Field(default_factory=list)
    target_industries: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)
    associated_campaigns: List[str] = Field(default_factory=list)
    known_tools: List[str] = Field(default_factory=list)
    first_observed: Optional[datetime] = None
    last_activity: Optional[datetime] = None


class Campaign(BaseModel):
    """Threat campaign tracking"""
    id: str = Field(default_factory=lambda: f"campaign_{uuid.uuid4().hex[:12]}")
    name: str
    description: str
    threat_actors: List[str] = Field(default_factory=list)
    start_date: datetime
    end_date: Optional[datetime] = None
    is_active: bool = True
    iocs: List[str] = Field(default_factory=list)
    target_industries: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM


# ============================================================================
# INCIDENT RESPONSE MODELS
# ============================================================================

class IRAction(BaseModel):
    """Individual IR action"""
    action: str
    priority: int
    estimated_time: str
    responsible_team: str
    status: str = "pending"


class ContainmentPlan(BaseModel):
    """Containment strategy"""
    incident_id: str
    immediate_actions: List[IRAction]
    isolation_steps: List[str]
    network_segmentation: List[str]
    account_actions: List[str]


class EradicationStrategy(BaseModel):
    """Eradication plan"""
    incident_id: str
    malware_removal: List[str]
    vulnerability_patching: List[str]
    credential_rotation: List[str]
    system_hardening: List[str]


class RecoveryPlan(BaseModel):
    """Recovery checklist"""
    incident_id: str
    system_restoration: List[IRAction]
    data_recovery: List[str]
    service_resumption: List[str]
    validation_steps: List[str]


class IRPlan(BaseModel):
    """Complete Incident Response Plan"""
    id: str = Field(default_factory=lambda: f"irplan_{uuid.uuid4().hex[:12]}")
    incident_id: str
    incident_type: IncidentType
    severity: Severity
    created_at: datetime = Field(default_factory=datetime.utcnow)
    containment: ContainmentPlan
    eradication: EradicationStrategy
    recovery: RecoveryPlan
    immediate_actions: List[IRAction]
    short_term_actions: List[IRAction]
    long_term_hardening: List[str]
    forensic_preservation: List[str]
    evidence_collection: List[str]
    chain_of_custody: List[Dict[str, Any]] = Field(default_factory=list)
    attacker_dwell_time: Optional[int] = None
    infection_vector: Optional[str] = None
    initial_compromise_time: Optional[datetime] = None
    detection_time: Optional[datetime] = None
    executive_summary: str
    technical_details: str
    lessons_learned: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class ForensicEvidence(BaseModel):
    """Forensic evidence tracking"""
    id: str = Field(default_factory=lambda: f"evidence_{uuid.uuid4().hex[:12]}")
    incident_id: str
    evidence_type: str
    collected_by: str
    collection_time: datetime
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    description: str
    chain_of_custody: List[Dict[str, Any]] = Field(default_factory=list)
