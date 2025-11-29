"""
Event Correlation Engine
Multi-source event correlation for attack chain detection
"""
from datetime import datetime, timedelta
from typing import List, Dict, Set
from collections import defaultdict
from models import LogEvent, Anomaly, CorrelatedEvent


class EventCorrelator:
    """Correlate events across multiple sources to detect attack chains"""
    
    def __init__(self, time_window_minutes: int = 60):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.attack_patterns = self._load_attack_patterns()
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Define known attack chain patterns"""
        return {
            "lateral_movement": [
                "failed_login", "successful_login", "privilege_escalation",
                "unusual_process", "network_connection"
            ],
            "data_exfiltration": [
                "unusual_data_access", "large_data_transfer", "external_connection",
                "compression_activity", "encryption_activity"
            ],
            "ransomware": [
                "suspicious_process", "file_encryption", "mass_file_modification",
                "backup_deletion", "ransom_note"
            ],
            "reconnaissance": [
                "port_scanning", "network_enumeration", "dns_queries",
                "vulnerability_scanning"
            ]
        }
    
    def correlate_events(self, logs: List[LogEvent], anomalies: List[Anomaly]) -> List[CorrelatedEvent]:
        """Correlate events to detect attack chains"""
        correlated = []
        
        # Group events by entity (user, IP, host)
        entity_events = self._group_by_entity(logs, anomalies)
        
        # Detect attack chains for each entity
        for entity, events in entity_events.items():
            correlated.extend(self._detect_attack_chains(entity, events))
        
        return correlated
    
    def _group_by_entity(self, logs: List[LogEvent], anomalies: List[Anomaly]) -> Dict[str, List]:
        """Group events by affected entity"""
        entity_events = defaultdict(list)
        
        for log in logs:
            entities = set()
            if log.user:
                entities.add(f"user:{log.user}")
            if log.source_ip:
                entities.add(f"ip:{log.source_ip}")
            if log.hostname:
                entities.add(f"host:{log.hostname}")
            
            for entity in entities:
                entity_events[entity].append(('log', log))
        
        for anomaly in anomalies:
            entity_type = self._infer_entity_type(anomaly.affected_entity)
            entity_key = f"{entity_type}:{anomaly.affected_entity}"
            entity_events[entity_key].append(('anomaly', anomaly))
        
        return entity_events
    
    def _infer_entity_type(self, entity: str) -> str:
        """Infer entity type from entity string"""
        if '@' in entity:
            return 'user'
        elif '.' in entity and entity.replace('.', '').isdigit():
            return 'ip'
        else:
            return 'host'
    
    def _detect_attack_chains(self, entity: str, events: List[tuple]) -> List[CorrelatedEvent]:
        """Detect attack chains for a specific entity"""
        correlated = []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x[1].timestamp)
        
        # Detect lateral movement
        lateral = self._detect_lateral_movement(entity, sorted_events)
        if lateral:
            correlated.append(lateral)
        
        # Detect data exfiltration
        exfil = self._detect_data_exfiltration(entity, sorted_events)
        if exfil:
            correlated.append(exfil)
        
        # Detect ransomware behavior
        ransomware = self._detect_ransomware(entity, sorted_events)
        if ransomware:
            correlated.append(ransomware)
        
        # Detect reconnaissance
        recon = self._detect_reconnaissance(entity, sorted_events)
        if recon:
            correlated.append(recon)
        
        return correlated
    
    def _detect_lateral_movement(self, entity: str, events: List[tuple]) -> CorrelatedEvent:
        """Detect lateral movement patterns"""
        # Look for: failed logins -> successful login -> privilege escalation -> unusual activity
        failed_logins = []
        successful_logins = []
        priv_esc = []
        unusual_activity = []
        
        for event_type, event in events:
            if event_type == 'log':
                if 'failed' in event.message.lower() and 'login' in event.message.lower():
                    failed_logins.append(event.id)
                elif 'success' in event.message.lower() and 'login' in event.message.lower():
                    successful_logins.append(event.id)
                elif any(kw in event.message.lower() for kw in ['sudo', 'admin', 'privilege', 'escalat']):
                    priv_esc.append(event.id)
            elif event_type == 'anomaly':
                if event.anomaly_type in ['unusual_process_activity', 'suspicious_process_execution']:
                    unusual_activity.append(event.id)
        
        # If we have the pattern, create correlated event
        if failed_logins and successful_logins and (priv_esc or unusual_activity):
            return CorrelatedEvent(
                timestamp=datetime.utcnow(),
                event_ids=failed_logins[:3] + successful_logins[:2] + priv_esc[:2] + unusual_activity[:2],
                attack_stage="lateral_movement",
                description=f"Lateral movement detected for {entity}: failed logins followed by successful access and privilege escalation",
                confidence=0.85,
                mitre_techniques=["T1078", "T1021", "T1068"]  # Valid Accounts, Remote Services, Exploitation for Privilege Escalation
            )
        
        return None
    
    def _detect_data_exfiltration(self, entity: str, events: List[tuple]) -> CorrelatedEvent:
        """Detect data exfiltration patterns"""
        data_access = []
        large_transfers = []
        external_connections = []
        
        for event_type, event in events:
            if event_type == 'anomaly':
                if event.anomaly_type == 'unusual_data_access':
                    data_access.append(event.id)
                elif event.anomaly_type == 'high_connection_volume':
                    large_transfers.append(event.id)
            elif event_type == 'log':
                # Check for external IPs (simplified check)
                if event.dest_ip and not event.dest_ip.startswith(('10.', '172.', '192.168.')):
                    external_connections.append(event.id)
        
        if data_access and (large_transfers or len(external_connections) > 5):
            return CorrelatedEvent(
                timestamp=datetime.utcnow(),
                event_ids=data_access[:3] + large_transfers[:2] + external_connections[:5],
                attack_stage="exfiltration",
                description=f"Potential data exfiltration detected for {entity}: unusual data access followed by large external transfers",
                confidence=0.75,
                mitre_techniques=["T1048", "T1041", "T1567"]  # Exfiltration Over Alternative Protocol, Exfiltration Over C2 Channel, Exfiltration Over Web Service
            )
        
        return None
    
    def _detect_ransomware(self, entity: str, events: List[tuple]) -> CorrelatedEvent:
        """Detect ransomware behavior"""
        suspicious_processes = []
        file_operations = []
        
        for event_type, event in events:
            if event_type == 'anomaly':
                if event.anomaly_type == 'suspicious_process_execution':
                    suspicious_processes.append(event.id)
            elif event_type == 'log':
                if any(kw in event.message.lower() for kw in ['encrypt', 'crypt', 'ransom', 'locked', '.encrypted']):
                    file_operations.append(event.id)
        
        if suspicious_processes and file_operations:
            return CorrelatedEvent(
                timestamp=datetime.utcnow(),
                event_ids=suspicious_processes[:3] + file_operations[:5],
                attack_stage="impact",
                description=f"Ransomware behavior detected for {entity}: suspicious process execution with file encryption activity",
                confidence=0.9,
                mitre_techniques=["T1486", "T1490"]  # Data Encrypted for Impact, Inhibit System Recovery
            )
        
        return None
    
    def _detect_reconnaissance(self, entity: str, events: List[tuple]) -> CorrelatedEvent:
        """Detect reconnaissance activity"""
        scanning = []
        
        for event_type, event in events:
            if event_type == 'anomaly':
                if event.anomaly_type in ['port_scanning', 'high_connection_volume']:
                    scanning.append(event.id)
        
        if len(scanning) >= 2:
            return CorrelatedEvent(
                timestamp=datetime.utcnow(),
                event_ids=scanning,
                attack_stage="reconnaissance",
                description=f"Reconnaissance activity detected from {entity}: network scanning and enumeration",
                confidence=0.8,
                mitre_techniques=["T1046", "T1018", "T1595"]  # Network Service Scanning, Remote System Discovery, Active Scanning
            )
        
        return None
