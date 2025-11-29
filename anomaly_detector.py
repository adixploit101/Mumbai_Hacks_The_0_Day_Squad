"""
Anomaly Detection Engine
Behavior-based anomaly detection using statistical methods
"""
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from models import LogEvent, Anomaly, BaselineProfile
from database import SecurityDatabase


class AnomalyDetector:
    """Detect anomalies using behavior-based analysis"""
    
    def __init__(self, db: SecurityDatabase, sensitivity: float = 0.7):
        self.db = db
        self.sensitivity = sensitivity
        self.baselines: Dict[str, BaselineProfile] = {}
        self.isolation_forests: Dict[str, IsolationForest] = {}
    
    def detect_anomalies(self, logs: List[LogEvent]) -> List[Anomaly]:
        """Detect anomalies in log events"""
        anomalies = []
        
        # Group logs by entity
        user_logs = defaultdict(list)
        ip_logs = defaultdict(list)
        host_logs = defaultdict(list)
        
        for log in logs:
            if log.user:
                user_logs[log.user].append(log)
            if log.source_ip:
                ip_logs[log.source_ip].append(log)
            if log.hostname:
                host_logs[log.hostname].append(log)
        
        # Detect user anomalies
        for user, user_events in user_logs.items():
            anomalies.extend(self._detect_user_anomalies(user, user_events))
        
        # Detect IP anomalies
        for ip, ip_events in ip_logs.items():
            anomalies.extend(self._detect_ip_anomalies(ip, ip_events))
        
        # Detect host anomalies
        for host, host_events in host_logs.items():
            anomalies.extend(self._detect_host_anomalies(host, host_events))
        
        return anomalies
    
    def _detect_user_anomalies(self, user: str, events: List[LogEvent]) -> List[Anomaly]:
        """Detect user behavior anomalies"""
        anomalies = []
        
        # Check for unusual login times
        login_times = [e.timestamp.hour for e in events if 'login' in e.message.lower() or 'auth' in e.message.lower()]
        if login_times:
            anomaly = self._check_unusual_time(user, login_times, "login")
            if anomaly:
                anomalies.append(anomaly)
        
        # Check for failed login attempts
        failed_logins = [e for e in events if 'failed' in e.message.lower() and 'login' in e.message.lower()]
        if len(failed_logins) >= 5:
            anomalies.append(Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="brute_force_attempt",
                description=f"Multiple failed login attempts detected for user {user}",
                score=min(len(failed_logins) * 10, 100),
                confidence=0.85,
                affected_entity=user,
                observed_value=float(len(failed_logins)),
                baseline_value=1.0,
                related_logs=[e.id for e in failed_logins],
                explanation=f"Detected {len(failed_logins)} failed login attempts in short time window, indicating possible brute force attack"
            ))
        
        # Check for unusual data access patterns
        data_access = [e for e in events if any(kw in e.message.lower() for kw in ['read', 'download', 'access', 'view'])]
        if len(data_access) > 50:  # Threshold for unusual activity
            anomalies.append(Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="unusual_data_access",
                description=f"Unusual data access volume for user {user}",
                score=70,
                confidence=0.7,
                affected_entity=user,
                observed_value=float(len(data_access)),
                baseline_value=10.0,
                related_logs=[e.id for e in data_access[:20]],
                explanation=f"User accessed {len(data_access)} resources, significantly above normal baseline of ~10"
            ))
        
        return anomalies
    
    def _detect_ip_anomalies(self, ip: str, events: List[LogEvent]) -> List[Anomaly]:
        """Detect IP-based anomalies"""
        anomalies = []
        
        # Check for port scanning
        unique_ports = set()
        for e in events:
            if e.dest_port:
                unique_ports.add(e.dest_port)
        
        if len(unique_ports) > 20:  # Accessing many different ports
            anomalies.append(Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="port_scanning",
                description=f"Potential port scanning detected from {ip}",
                score=85,
                confidence=0.9,
                affected_entity=ip,
                observed_value=float(len(unique_ports)),
                baseline_value=3.0,
                related_logs=[e.id for e in events[:20]],
                explanation=f"IP {ip} accessed {len(unique_ports)} different ports, indicating reconnaissance activity"
            ))
        
        # Check for high connection volume
        if len(events) > 100:
            anomalies.append(Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="high_connection_volume",
                description=f"Unusually high connection volume from {ip}",
                score=60,
                confidence=0.75,
                affected_entity=ip,
                observed_value=float(len(events)),
                baseline_value=20.0,
                related_logs=[e.id for e in events[:20]],
                explanation=f"IP {ip} generated {len(events)} connections, significantly above normal baseline"
            ))
        
        # Check for denied connections (potential attack attempts)
        denied = [e for e in events if e.action and 'deny' in e.action.lower()]
        if len(denied) > 10:
            anomalies.append(Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="repeated_access_denial",
                description=f"Multiple access denials for {ip}",
                score=75,
                confidence=0.8,
                affected_entity=ip,
                observed_value=float(len(denied)),
                baseline_value=2.0,
                related_logs=[e.id for e in denied],
                explanation=f"IP {ip} had {len(denied)} denied access attempts, suggesting unauthorized access attempts"
            ))
        
        return anomalies
    
    def _detect_host_anomalies(self, hostname: str, events: List[LogEvent]) -> List[Anomaly]:
        """Detect host-based anomalies"""
        anomalies = []
        
        # Check for unusual process execution
        processes = [e.process for e in events if e.process]
        unique_processes = set(processes)
        
        if len(unique_processes) > 30:
            anomalies.append(Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="unusual_process_activity",
                description=f"Unusual process activity on {hostname}",
                score=65,
                confidence=0.7,
                affected_entity=hostname,
                observed_value=float(len(unique_processes)),
                baseline_value=15.0,
                related_logs=[e.id for e in events[:20]],
                explanation=f"Host {hostname} executed {len(unique_processes)} different processes, above normal baseline"
            ))
        
        # Check for suspicious process names
        suspicious_keywords = ['mimikatz', 'psexec', 'powershell -enc', 'cmd.exe', 'nc.exe', 'netcat']
        suspicious_events = [e for e in events if e.process and any(kw in e.process.lower() for kw in suspicious_keywords)]
        
        if suspicious_events:
            anomalies.append(Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="suspicious_process_execution",
                description=f"Suspicious process execution on {hostname}",
                score=90,
                confidence=0.85,
                affected_entity=hostname,
                related_logs=[e.id for e in suspicious_events],
                explanation=f"Detected execution of suspicious processes commonly used in attacks: {', '.join(set(e.process for e in suspicious_events[:5]))}"
            ))
        
        return anomalies
    
    def _check_unusual_time(self, entity: str, times: List[int], activity: str) -> Optional[Anomaly]:
        """Check for unusual activity times"""
        # Business hours: 8 AM - 6 PM
        off_hours = [t for t in times if t < 8 or t > 18]
        
        if len(off_hours) / len(times) > 0.7:  # More than 70% off-hours activity
            return Anomaly(
                timestamp=datetime.utcnow(),
                anomaly_type="unusual_activity_time",
                description=f"Unusual {activity} time for {entity}",
                score=55,
                confidence=0.65,
                affected_entity=entity,
                observed_value=float(len(off_hours)),
                baseline_value=float(len(times) * 0.2),
                related_logs=[],
                explanation=f"Entity {entity} performed {activity} during off-hours {len(off_hours)} times out of {len(times)} total, suggesting unusual behavior"
            )
        
        return None
    
    def build_baseline(self, entity_type: str, entity_id: str, metric: str, values: List[float]) -> BaselineProfile:
        """Build behavioral baseline"""
        if not values:
            return None
        
        baseline = BaselineProfile(
            entity_type=entity_type,
            entity_id=entity_id,
            metric=metric,
            baseline_value=float(np.mean(values)),
            std_deviation=float(np.std(values)),
            sample_size=len(values),
            last_updated=datetime.utcnow()
        )
        
        self.baselines[f"{entity_type}:{entity_id}:{metric}"] = baseline
        return baseline
