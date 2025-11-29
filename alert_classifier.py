"""
Alert Classification System
Classify alerts by severity and eliminate false positives
"""
from datetime import datetime
from typing import List, Optional
from models import Alert, Anomaly, CorrelatedEvent, Severity, IncidentType
from mitre_mapper import MITREMapper


class AlertClassifier:
    """Classify and prioritize security alerts"""
    
    def __init__(self, mitre_mapper: MITREMapper):
        self.mitre_mapper = mitre_mapper
        self.false_positive_patterns = self._load_fp_patterns()
    
    def _load_fp_patterns(self) -> dict:
        """Load false positive patterns"""
        return {
            "whitelisted_ips": set(["10.0.0.1", "192.168.1.1"]),  # Internal trusted IPs
            "scheduled_tasks": set(["backup_job", "maintenance_script"]),
            "approved_tools": set(["nmap_scan_approved", "vulnerability_scanner"])
        }
    
    def classify_anomaly(self, anomaly: Anomaly) -> Alert:
        """Classify anomaly into alert"""
        # Check for false positive
        is_fp, fp_reason = self._check_false_positive(anomaly)
        
        # Determine severity
        severity = self._determine_severity(anomaly.score, anomaly.anomaly_type)
        
        # Map to MITRE techniques
        mitre_techniques = self.mitre_mapper.map_to_techniques(
            anomaly.description,
            anomaly.anomaly_type
        )
        
        # Generate explanation
        explanation = self._generate_explanation(anomaly, severity, mitre_techniques)
        
        return Alert(
            timestamp=datetime.utcnow(),
            severity=severity,
            title=f"{anomaly.anomaly_type.replace('_', ' ').title()} Detected",
            description=anomaly.description,
            affected_assets=[anomaly.affected_entity],
            source_events=[anomaly.id],
            mitre_techniques=mitre_techniques,
            confidence_score=anomaly.score,
            is_false_positive=is_fp,
            false_positive_reason=fp_reason,
            explanation=explanation
        )
    
    def classify_correlated_event(self, event: CorrelatedEvent) -> Alert:
        """Classify correlated event into alert"""
        # Correlated events are typically high severity
        severity = self._determine_severity_from_stage(event.attack_stage)
        
        # Generate explanation
        explanation = f"""
ATTACK CHAIN DETECTED

Attack Stage: {event.attack_stage.upper()}
Confidence: {event.confidence * 100:.1f}%

This alert was triggered by correlating multiple security events that match a known attack pattern.

MITRE ATT&CK Techniques:
{', '.join(event.mitre_techniques)}

Event Correlation:
- {len(event.event_ids)} related events detected
- Events occurred within correlation time window
- Pattern matches known {event.attack_stage} behavior

Why This is Suspicious:
{event.description}

Recommended Actions:
1. Investigate all correlated events immediately
2. Check for additional indicators of compromise
3. Review affected systems for signs of persistence
4. Consider initiating incident response procedures
"""
        
        return Alert(
            timestamp=datetime.utcnow(),
            severity=severity,
            title=f"{event.attack_stage.replace('_', ' ').title()} Attack Chain Detected",
            description=event.description,
            affected_assets=[],  # Will be populated from events
            source_events=event.event_ids,
            mitre_techniques=event.mitre_techniques,
            confidence_score=event.confidence * 100,
            is_false_positive=False,
            explanation=explanation
        )
    
    def _determine_severity(self, score: float, anomaly_type: str) -> Severity:
        """Determine alert severity based on score and type"""
        # Critical severity anomalies
        critical_types = [
            "ransomware", "data_exfiltration", "suspicious_process_execution",
            "credential_dumping"
        ]
        
        if anomaly_type in critical_types or score >= 90:
            return Severity.CRITICAL
        elif score >= 70:
            return Severity.HIGH
        elif score >= 40:
            return Severity.MEDIUM
        elif score >= 20:
            return Severity.LOW
        else:
            return Severity.INFO
    
    def _determine_severity_from_stage(self, attack_stage: str) -> Severity:
        """Determine severity from attack stage"""
        severity_map = {
            "reconnaissance": Severity.MEDIUM,
            "initial_access": Severity.HIGH,
            "execution": Severity.HIGH,
            "persistence": Severity.HIGH,
            "privilege_escalation": Severity.CRITICAL,
            "defense_evasion": Severity.HIGH,
            "credential_access": Severity.CRITICAL,
            "discovery": Severity.MEDIUM,
            "lateral_movement": Severity.CRITICAL,
            "collection": Severity.HIGH,
            "exfiltration": Severity.CRITICAL,
            "impact": Severity.CRITICAL
        }
        return severity_map.get(attack_stage, Severity.MEDIUM)
    
    def _check_false_positive(self, anomaly: Anomaly) -> tuple[bool, Optional[str]]:
        """Check if anomaly is likely a false positive"""
        # Check whitelisted entities
        if anomaly.affected_entity in self.false_positive_patterns["whitelisted_ips"]:
            return True, f"Entity {anomaly.affected_entity} is whitelisted"
        
        # Check for approved scheduled tasks
        if anomaly.anomaly_type == "unusual_activity_time":
            for task in self.false_positive_patterns["scheduled_tasks"]:
                if task in anomaly.description.lower():
                    return True, f"Activity matches approved scheduled task: {task}"
        
        # Check for approved security tools
        if anomaly.anomaly_type == "port_scanning":
            for tool in self.false_positive_patterns["approved_tools"]:
                if tool in anomaly.description.lower():
                    return True, f"Activity from approved security tool: {tool}"
        
        return False, None
    
    def _generate_explanation(self, anomaly: Anomaly, severity: Severity, 
                            mitre_techniques: List[str]) -> str:
        """Generate detailed alert explanation"""
        technique_details = []
        for tid in mitre_techniques[:3]:  # Top 3 techniques
            details = self.mitre_mapper.get_technique_details(tid)
            if details:
                technique_details.append(f"- {tid}: {details['name']}")
        
        return f"""
ALERT EXPLANATION

Anomaly Type: {anomaly.anomaly_type.replace('_', ' ').title()}
Severity: {severity.value}
Confidence Score: {anomaly.score:.1f}/100

WHY THIS ALERT WAS TRIGGERED:
{anomaly.explanation}

OBSERVED BEHAVIOR:
- Baseline Value: {anomaly.baseline_value if anomaly.baseline_value else 'N/A'}
- Observed Value: {anomaly.observed_value if anomaly.observed_value else 'N/A'}
- Deviation: {abs(anomaly.observed_value - anomaly.baseline_value) if (anomaly.observed_value and anomaly.baseline_value) else 'N/A'}

MITRE ATT&CK MAPPING:
{chr(10).join(technique_details) if technique_details else 'No specific techniques mapped'}

AFFECTED ENTITY:
{anomaly.affected_entity}

DETECTION LOGIC:
This alert was generated using behavior-based anomaly detection. The observed activity 
significantly deviates from established baselines for this entity.

RECOMMENDED ACTIONS:
1. Investigate the affected entity immediately
2. Review related log events for additional context
3. Check for other anomalies from the same entity
4. Consider escalating to incident response if confirmed malicious
"""
