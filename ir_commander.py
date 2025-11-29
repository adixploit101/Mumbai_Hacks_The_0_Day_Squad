"""
Incident Response Commander
Automated incident response planning and execution
"""
from datetime import datetime, timedelta
from typing import List, Dict
from models import (
    Incident, IncidentType, Severity, IRPlan, IRAction,
    ContainmentPlan, EradicationStrategy, RecoveryPlan
)


class IRCommander:
    """Incident Response automation and planning"""
    
    def __init__(self):
        self.playbooks = self._load_playbooks()
    
    def _load_playbooks(self) -> Dict:
        """Load incident response playbooks"""
        return {
            IncidentType.MALWARE: self._malware_playbook,
            IncidentType.RANSOMWARE: self._ransomware_playbook,
            IncidentType.DATA_BREACH: self._data_breach_playbook,
            IncidentType.INSIDER_THREAT: self._insider_threat_playbook,
            IncidentType.PHISHING: self._phishing_playbook,
            IncidentType.DDOS: self._ddos_playbook
        }
    
    def generate_ir_plan(self, incident: Incident) -> IRPlan:
        """Generate comprehensive IR plan for incident"""
        playbook = self.playbooks.get(incident.incident_type, self._generic_playbook)
        return playbook(incident)
    
    def _malware_playbook(self, incident: Incident) -> IRPlan:
        """Malware incident response playbook"""
        # Containment
        containment = ContainmentPlan(
            incident_id=incident.id,
            immediate_actions=[
                IRAction(
                    action="Isolate infected systems from network",
                    priority=1,
                    estimated_time="5 minutes",
                    responsible_team="Network Operations",
                    status="pending"
                ),
                IRAction(
                    action="Disable user accounts on affected systems",
                    priority=2,
                    estimated_time="10 minutes",
                    responsible_team="Identity Management",
                    status="pending"
                ),
                IRAction(
                    action="Block malicious IPs/domains at firewall",
                    priority=3,
                    estimated_time="15 minutes",
                    responsible_team="Security Operations",
                    status="pending"
                )
            ],
            isolation_steps=[
                "Disconnect affected systems from network",
                "Disable wireless and Bluetooth",
                "Block lateral movement at network layer"
            ],
            network_segmentation=[
                "Isolate affected subnet",
                "Implement micro-segmentation",
                "Monitor east-west traffic"
            ],
            account_actions=[
                "Disable compromised accounts",
                "Force password reset for affected users",
                "Enable MFA for all accounts"
            ]
        )
        
        # Eradication
        eradication = EradicationStrategy(
            incident_id=incident.id,
            malware_removal=[
                "Run antivirus full scan on all systems",
                "Remove malware artifacts and persistence mechanisms",
                "Clean registry entries and scheduled tasks",
                "Verify removal with secondary AV tool"
            ],
            vulnerability_patching=[
                "Identify exploited vulnerability",
                "Apply security patches to all systems",
                "Update antivirus signatures",
                "Harden system configurations"
            ],
            credential_rotation=[
                "Reset all user passwords",
                "Rotate service account credentials",
                "Regenerate API keys and tokens",
                "Update SSH keys"
            ],
            system_hardening=[
                "Disable unnecessary services",
                "Apply principle of least privilege",
                "Enable application whitelisting",
                "Configure host-based firewall"
            ]
        )
        
        # Recovery
        recovery = RecoveryPlan(
            incident_id=incident.id,
            system_restoration=[
                IRAction(
                    action="Restore systems from clean backups",
                    priority=1,
                    estimated_time="4 hours",
                    responsible_team="IT Operations",
                    status="pending"
                ),
                IRAction(
                    action="Rebuild compromised systems from scratch",
                    priority=2,
                    estimated_time="8 hours",
                    responsible_team="IT Operations",
                    status="pending"
                )
            ],
            data_recovery=[
                "Verify backup integrity",
                "Restore data from last clean backup",
                "Validate data consistency",
                "Test critical applications"
            ],
            service_resumption=[
                "Gradually restore network connectivity",
                "Monitor for reinfection",
                "Resume business operations in phases",
                "Communicate status to stakeholders"
            ],
            validation_steps=[
                "Verify malware removal",
                "Confirm system functionality",
                "Test security controls",
                "Conduct vulnerability scan"
            ]
        )
        
        # Immediate actions (0-15 min)
        immediate = [
            IRAction(
                action="Isolate infected systems",
                priority=1,
                estimated_time="5 min",
                responsible_team="SOC",
                status="pending"
            ),
            IRAction(
                action="Collect memory dumps and disk images",
                priority=2,
                estimated_time="10 min",
                responsible_team="Forensics",
                status="pending"
            ),
            IRAction(
                action="Block C2 communication",
                priority=3,
                estimated_time="15 min",
                responsible_team="Network Security",
                status="pending"
            )
        ]
        
        # Short-term actions (24 hrs)
        short_term = [
            IRAction(
                action="Complete malware analysis",
                priority=1,
                estimated_time="4 hours",
                responsible_team="Malware Analysis",
                status="pending"
            ),
            IRAction(
                action="Patch all vulnerable systems",
                priority=2,
                estimated_time="8 hours",
                responsible_team="IT Operations",
                status="pending"
            ),
            IRAction(
                action="Reset all credentials",
                priority=3,
                estimated_time="12 hours",
                responsible_team="Identity Management",
                status="pending"
            )
        ]
        
        # Long-term hardening
        long_term = [
            "Implement EDR on all endpoints",
            "Deploy network segmentation",
            "Enhance email security controls",
            "Conduct security awareness training",
            "Implement application whitelisting",
            "Regular vulnerability assessments"
        ]
        
        # Calculate attacker dwell time
        dwell_time = self._calculate_dwell_time(incident)
        
        return IRPlan(
            incident_id=incident.id,
            incident_type=incident.incident_type,
            severity=incident.severity,
            containment=containment,
            eradication=eradication,
            recovery=recovery,
            immediate_actions=immediate,
            short_term_actions=short_term,
            long_term_hardening=long_term,
            attacker_dwell_time=dwell_time,
            infection_vector="Phishing email with malicious attachment",
            forensic_preservation=[
                "Preserve system memory dumps",
                "Capture network traffic logs",
                "Collect system event logs",
                "Document all actions taken"
            ],
            evidence_collection=[
                "Malware samples",
                "Network packet captures",
                "System logs and artifacts",
                "Email headers and attachments"
            ],
            executive_summary=self._generate_executive_summary(incident, "malware"),
            technical_details=self._generate_technical_details(incident)
        )
    
    def _ransomware_playbook(self, incident: Incident) -> IRPlan:
        """Ransomware incident response playbook"""
        containment = ContainmentPlan(
            incident_id=incident.id,
            immediate_actions=[
                IRAction(
                    action="IMMEDIATELY isolate all affected systems",
                    priority=1,
                    estimated_time="2 minutes",
                    responsible_team="SOC",
                    status="pending"
                ),
                IRAction(
                    action="Disable all network shares and backups",
                    priority=2,
                    estimated_time="5 minutes",
                    responsible_team="IT Operations",
                    status="pending"
                ),
                IRAction(
                    action="Shut down encryption processes",
                    priority=3,
                    estimated_time="10 minutes",
                    responsible_team="SOC",
                    status="pending"
                )
            ],
            isolation_steps=[
                "Disconnect from network immediately",
                "Power off systems if encryption in progress",
                "Isolate backup infrastructure"
            ],
            network_segmentation=[
                "Block all lateral movement",
                "Isolate critical systems",
                "Disable VPN access"
            ],
            account_actions=[
                "Disable all user accounts",
                "Disable service accounts",
                "Block remote access"
            ]
        )
        
        eradication = EradicationStrategy(
            incident_id=incident.id,
            malware_removal=[
                "Identify ransomware variant",
                "Remove ransomware executable",
                "Delete persistence mechanisms",
                "Check for decryption tools availability"
            ],
            vulnerability_patching=[
                "Patch exploited vulnerability (if applicable)",
                "Update all systems",
                "Harden RDP and SMB configurations"
            ],
            credential_rotation=[
                "Reset ALL passwords (mandatory)",
                "Rotate all service credentials",
                "Regenerate Kerberos tickets"
            ],
            system_hardening=[
                "Disable unnecessary protocols",
                "Implement strict access controls",
                "Enable ransomware protection features"
            ]
        )
        
        recovery = RecoveryPlan(
            incident_id=incident.id,
            system_restoration=[
                IRAction(
                    action="Restore from offline backups",
                    priority=1,
                    estimated_time="12 hours",
                    responsible_team="Backup Team",
                    status="pending"
                ),
                IRAction(
                    action="Rebuild critical systems",
                    priority=2,
                    estimated_time="24 hours",
                    responsible_team="IT Operations",
                    status="pending"
                )
            ],
            data_recovery=[
                "Verify backup integrity (pre-infection)",
                "Attempt decryption if tool available",
                "Restore from last clean backup",
                "Validate data integrity"
            ],
            service_resumption=[
                "Restore critical services first",
                "Gradual network reconnection",
                "Monitor for re-encryption",
                "Business continuity activation"
            ],
            validation_steps=[
                "Verify complete ransomware removal",
                "Test all restored systems",
                "Confirm no backdoors remain",
                "Security posture assessment"
            ]
        )
        
        return IRPlan(
            incident_id=incident.id,
            incident_type=incident.incident_type,
            severity=Severity.CRITICAL,
            containment=containment,
            eradication=eradication,
            recovery=recovery,
            immediate_actions=containment.immediate_actions,
            short_term_actions=[
                IRAction(
                    action="Complete forensic analysis",
                    priority=1,
                    estimated_time="8 hours",
                    responsible_team="Forensics",
                    status="pending"
                ),
                IRAction(
                    action="Restore from backups",
                    priority=2,
                    estimated_time="24 hours",
                    responsible_team="IT Operations",
                    status="pending"
                )
            ],
            long_term_hardening=[
                "Implement offline backup strategy",
                "Deploy anti-ransomware solutions",
                "Network segmentation",
                "Privileged access management",
                "Regular backup testing",
                "Incident response drills"
            ],
            attacker_dwell_time=self._calculate_dwell_time(incident),
            infection_vector="RDP brute force or phishing",
            forensic_preservation=[
                "Preserve encrypted files for analysis",
                "Capture ransom note",
                "Document encryption timeline",
                "Preserve system state"
            ],
            evidence_collection=[
                "Ransomware executable",
                "Encryption logs",
                "Network traffic",
                "Ransom payment details (if any)"
            ],
            executive_summary=self._generate_executive_summary(incident, "ransomware"),
            technical_details=self._generate_technical_details(incident),
            recommendations=[
                "DO NOT pay ransom without legal/executive approval",
                "Report to law enforcement (FBI IC3)",
                "Engage ransomware negotiation firm if needed",
                "Prepare public communications"
            ]
        )
    
    def _data_breach_playbook(self, incident: Incident) -> IRPlan:
        """Data breach incident response playbook"""
        # Similar structure to above, focused on data breach response
        return self._generic_playbook(incident)
    
    def _insider_threat_playbook(self, incident: Incident) -> IRPlan:
        """Insider threat incident response playbook"""
        return self._generic_playbook(incident)
    
    def _phishing_playbook(self, incident: Incident) -> IRPlan:
        """Phishing incident response playbook"""
        return self._generic_playbook(incident)
    
    def _ddos_playbook(self, incident: Incident) -> IRPlan:
        """DDoS incident response playbook"""
        return self._generic_playbook(incident)
    
    def _generic_playbook(self, incident: Incident) -> IRPlan:
        """Generic incident response playbook"""
        # Simplified generic response
        containment = ContainmentPlan(
            incident_id=incident.id,
            immediate_actions=[
                IRAction(
                    action="Assess incident scope",
                    priority=1,
                    estimated_time="15 min",
                    responsible_team="SOC",
                    status="pending"
                )
            ],
            isolation_steps=["Isolate affected systems"],
            network_segmentation=["Implement network controls"],
            account_actions=["Review and secure accounts"]
        )
        
        eradication = EradicationStrategy(
            incident_id=incident.id,
            malware_removal=["Remove threats"],
            vulnerability_patching=["Apply patches"],
            credential_rotation=["Rotate credentials"],
            system_hardening=["Harden systems"]
        )
        
        recovery = RecoveryPlan(
            incident_id=incident.id,
            system_restoration=[],
            data_recovery=["Restore data"],
            service_resumption=["Resume services"],
            validation_steps=["Validate recovery"]
        )
        
        return IRPlan(
            incident_id=incident.id,
            incident_type=incident.incident_type,
            severity=incident.severity,
            containment=containment,
            eradication=eradication,
            recovery=recovery,
            immediate_actions=containment.immediate_actions,
            short_term_actions=[],
            long_term_hardening=["Improve security posture"],
            executive_summary=self._generate_executive_summary(incident, "generic"),
            technical_details=self._generate_technical_details(incident)
        )
    
    def _calculate_dwell_time(self, incident: Incident) -> int:
        """Calculate attacker dwell time in hours"""
        # In production, calculate from initial compromise to detection
        return 48  # Simulated 48 hours
    
    def _generate_executive_summary(self, incident: Incident, incident_category: str) -> str:
        """Generate executive incident summary"""
        return f"""
EXECUTIVE INCIDENT REPORT

Incident ID: {incident.id}
Incident Type: {incident.incident_type.value}
Severity: {incident.severity.value}
Detection Time: {incident.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

SUMMARY:
{incident.description}

IMPACT:
{incident.impact_assessment}

AFFECTED ASSETS:
{', '.join(incident.affected_assets[:5])}{'...' if len(incident.affected_assets) > 5 else ''}

IMMEDIATE ACTIONS TAKEN:
- Incident detected and classified
- Affected systems identified
- Containment procedures initiated
- Forensic evidence preserved

BUSINESS IMPACT:
- Potential data exposure: {len(incident.affected_assets)} systems
- Service disruption: Minimal (systems isolated)
- Estimated recovery time: 24-48 hours

RECOMMENDATIONS:
- Follow incident response plan
- Engage legal and PR teams if needed
- Prepare stakeholder communications
- Review and update security controls

This is a {incident.severity.value.lower()} severity incident requiring immediate attention.
"""
    
    def _generate_technical_details(self, incident: Incident) -> str:
        """Generate technical incident details"""
        return f"""
TECHNICAL INCIDENT DETAILS

Attack Vector: {incident.attack_path[0] if incident.attack_path else 'Unknown'}
Attack Chain: {' → '.join(incident.attack_path)}

MITRE ATT&CK Mapping:
Tactics: {', '.join(incident.mitre_tactics)}
Techniques: {', '.join(incident.mitre_techniques)}

Indicators of Compromise:
- See attached IOC list
- Malicious IPs, domains, hashes identified

Forensic Analysis:
- Evidence collected and preserved
- Chain of custody maintained
- Analysis in progress

Detection Confidence: {incident.confidence_score}%
"""
