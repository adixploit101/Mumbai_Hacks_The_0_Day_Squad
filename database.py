"""
Database interface for Security Platform
SQLite for development, easily upgradable to PostgreSQL/Elasticsearch
"""
import sqlite3
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
from models import *


class SecurityDatabase:
    def __init__(self, db_path: str = "security_platform.db"):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # SIEM Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS log_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    user TEXT,
                    hostname TEXT,
                    message TEXT,
                    raw_log TEXT,
                    metadata TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    description TEXT,
                    score REAL,
                    confidence REAL,
                    affected_entity TEXT,
                    explanation TEXT,
                    related_logs TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    affected_assets TEXT,
                    mitre_techniques TEXT,
                    confidence_score REAL,
                    is_false_positive INTEGER DEFAULT 0,
                    explanation TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    attack_path TEXT,
                    affected_assets TEXT,
                    impact_assessment TEXT,
                    recommended_actions TEXT,
                    confidence_score REAL,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT,
                    explanation TEXT,
                    status TEXT DEFAULT 'open'
                )
            """)
            
            # CTI Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id TEXT PRIMARY KEY,
                    indicator TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    source TEXT,
                    tags TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    ioc_id TEXT PRIMARY KEY,
                    indicator TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    geolocation TEXT,
                    asn TEXT,
                    asn_org TEXT,
                    malware_families TEXT,
                    campaigns TEXT,
                    threat_actors TEXT,
                    threat_category TEXT,
                    risk_score REAL,
                    confidence REAL,
                    first_seen TEXT,
                    last_seen TEXT,
                    sighting_count INTEGER DEFAULT 1,
                    enrichment_timestamp TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_actors (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    aliases TEXT,
                    description TEXT,
                    origin_country TEXT,
                    motivation TEXT,
                    target_industries TEXT,
                    ttps TEXT,
                    associated_campaigns TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    threat_actors TEXT,
                    start_date TEXT,
                    end_date TEXT,
                    is_active INTEGER DEFAULT 1,
                    iocs TEXT,
                    target_industries TEXT,
                    ttps TEXT,
                    severity TEXT
                )
            """)
            
            # IR Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ir_plans (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    containment TEXT,
                    eradication TEXT,
                    recovery TEXT,
                    immediate_actions TEXT,
                    short_term_actions TEXT,
                    long_term_hardening TEXT,
                    attacker_dwell_time INTEGER,
                    infection_vector TEXT,
                    executive_summary TEXT,
                    technical_details TEXT
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON log_events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON log_events(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator)")
            
            conn.commit()
    
    # ========================================================================
    # SIEM Operations
    # ========================================================================
    
    def insert_log(self, log: LogEvent):
        """Insert log event"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO log_events 
                (id, timestamp, source, source_ip, dest_ip, user, hostname, message, raw_log, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log.id, log.timestamp.isoformat(), log.source.value,
                log.source_ip, log.dest_ip, log.user, log.hostname,
                log.message, log.raw_log, json.dumps(log.metadata)
            ))
    
    def insert_anomaly(self, anomaly: Anomaly):
        """Insert anomaly"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO anomalies 
                (id, timestamp, anomaly_type, description, score, confidence, 
                 affected_entity, explanation, related_logs)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                anomaly.id, anomaly.timestamp.isoformat(), anomaly.anomaly_type,
                anomaly.description, anomaly.score, anomaly.confidence,
                anomaly.affected_entity, anomaly.explanation,
                json.dumps(anomaly.related_logs)
            ))
    
    def insert_alert(self, alert: Alert):
        """Insert alert"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts 
                (id, timestamp, severity, title, description, affected_assets,
                 mitre_techniques, confidence_score, is_false_positive, explanation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id, alert.timestamp.isoformat(), alert.severity.value,
                alert.title, alert.description, json.dumps(alert.affected_assets),
                json.dumps(alert.mitre_techniques), alert.confidence_score,
                1 if alert.is_false_positive else 0, alert.explanation
            ))
    
    def insert_incident(self, incident: Incident):
        """Insert incident"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incidents 
                (id, timestamp, incident_type, severity, title, description,
                 attack_path, affected_assets, impact_assessment, recommended_actions,
                 confidence_score, mitre_tactics, mitre_techniques, explanation, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.id, incident.timestamp.isoformat(), incident.incident_type.value,
                incident.severity.value, incident.title, incident.description,
                json.dumps(incident.attack_path), json.dumps(incident.affected_assets),
                incident.impact_assessment, json.dumps(incident.recommended_actions),
                incident.confidence_score, json.dumps(incident.mitre_tactics),
                json.dumps(incident.mitre_techniques), incident.explanation, incident.status
            ))
    
    def get_recent_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict]:
        """Get recent alerts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts"
            params = []
            
            if severity:
                query += " WHERE severity = ?"
                params.append(severity)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_incident_by_id(self, incident_id: str) -> Optional[Dict]:
        """Get incident by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_incident_stats(self) -> Dict[str, int]:
        """Get incident statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status, COUNT(*) as count FROM incidents GROUP BY status")
            rows = cursor.fetchall()
            stats = {row['status']: row['count'] for row in rows}
            return stats
    
    # ========================================================================
    # CTI Operations
    # ========================================================================
    
    def insert_ioc(self, ioc: IOC):
        """Insert IOC"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO iocs 
                (id, indicator, ioc_type, first_seen, last_seen, source, tags, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc.id, ioc.indicator, ioc.ioc_type.value,
                ioc.first_seen.isoformat(), ioc.last_seen.isoformat(),
                ioc.source, json.dumps(ioc.tags), 1 if ioc.is_active else 0
            ))
    
    def insert_threat_intel(self, intel: ThreatIntel):
        """Insert threat intelligence"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_intel 
                (ioc_id, indicator, ioc_type, geolocation, asn, asn_org,
                 malware_families, campaigns, threat_actors, threat_category,
                 risk_score, confidence, first_seen, last_seen, sighting_count,
                 enrichment_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                intel.ioc_id, intel.indicator, intel.ioc_type.value,
                json.dumps(intel.geolocation) if intel.geolocation else None,
                intel.asn, intel.asn_org,
                json.dumps(intel.malware_families), json.dumps(intel.campaigns),
                json.dumps(intel.threat_actors),
                intel.threat_category.value if intel.threat_category else None,
                intel.risk_score, intel.confidence,
                intel.first_seen.isoformat(), intel.last_seen.isoformat(),
                intel.sighting_count, intel.enrichment_timestamp.isoformat()
            ))
    
    def get_ioc_by_indicator(self, indicator: str) -> Optional[Dict]:
        """Get IOC by indicator value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ti.*, i.tags, i.source 
                FROM threat_intel ti
                LEFT JOIN iocs i ON ti.ioc_id = i.id
                WHERE ti.indicator = ?
            """, (indicator,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_threat_actors(self) -> List[Dict]:
        """Get all threat actors"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_actors")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_active_campaigns(self) -> List[Dict]:
        """Get active campaigns"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM campaigns WHERE is_active = 1")
            return [dict(row) for row in cursor.fetchall()]
    
    # ========================================================================
    # IR Operations
    # ========================================================================
    
    def insert_ir_plan(self, plan: IRPlan):
        """Insert IR plan"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ir_plans 
                (id, incident_id, incident_type, severity, created_at,
                 containment, eradication, recovery, immediate_actions,
                 short_term_actions, long_term_hardening, attacker_dwell_time,
                 infection_vector, executive_summary, technical_details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                plan.id, plan.incident_id, plan.incident_type.value,
                plan.severity.value, plan.created_at.isoformat(),
                json.dumps(plan.containment.dict()), json.dumps(plan.eradication.dict()),
                json.dumps(plan.recovery.dict()), json.dumps([a.dict() for a in plan.immediate_actions]),
                json.dumps([a.dict() for a in plan.short_term_actions]),
                json.dumps(plan.long_term_hardening), plan.attacker_dwell_time,
                plan.infection_vector, plan.executive_summary, plan.technical_details
            ))
    
    def get_ir_plan_by_incident(self, incident_id: str) -> Optional[Dict]:
        """Get IR plan for incident"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ir_plans WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
