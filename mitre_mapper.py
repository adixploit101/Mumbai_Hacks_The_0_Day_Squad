"""
MITRE ATT&CK Mapper
Maps detected activities to MITRE ATT&CK framework
"""
import json
from typing import List, Dict, Set, Optional
from pathlib import Path


class MITREMapper:
    """Map security events to MITRE ATT&CK techniques"""
    
    def __init__(self, data_file: str = "mitre_attack_data.json"):
        self.data_file = Path(data_file)
        self.techniques = self._load_mitre_data()
        self.behavior_mappings = self._create_behavior_mappings()
    
    def _load_mitre_data(self) -> Dict:
        """Load MITRE ATT&CK data"""
        if self.data_file.exists():
            with open(self.data_file, 'r') as f:
                return json.load(f)
        else:
            # Create basic MITRE data if file doesn't exist
            return self._create_basic_mitre_data()
    
    def _create_basic_mitre_data(self) -> Dict:
        """Create basic MITRE ATT&CK reference data"""
        data = {
            "techniques": {
                # Initial Access
                "T1078": {
                    "name": "Valid Accounts",
                    "tactic": "Initial Access",
                    "description": "Adversaries may obtain and abuse credentials of existing accounts",
                    "detection": ["unusual login times", "failed login attempts", "login from unusual location"]
                },
                "T1566": {
                    "name": "Phishing",
                    "tactic": "Initial Access",
                    "description": "Adversaries may send phishing messages to gain access",
                    "detection": ["suspicious email", "malicious attachment", "phishing link"]
                },
                
                # Execution
                "T1059": {
                    "name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "description": "Adversaries may abuse command and script interpreters",
                    "detection": ["powershell", "cmd.exe", "bash", "python"]
                },
                "T1203": {
                    "name": "Exploitation for Client Execution",
                    "tactic": "Execution",
                    "description": "Adversaries may exploit software vulnerabilities",
                    "detection": ["exploit", "vulnerability", "CVE"]
                },
                
                # Persistence
                "T1053": {
                    "name": "Scheduled Task/Job",
                    "tactic": "Persistence",
                    "description": "Adversaries may abuse task scheduling",
                    "detection": ["scheduled task", "cron", "at command"]
                },
                "T1547": {
                    "name": "Boot or Logon Autostart Execution",
                    "tactic": "Persistence",
                    "description": "Adversaries may configure system settings to automatically execute",
                    "detection": ["registry run key", "startup folder", "autostart"]
                },
                
                # Privilege Escalation
                "T1068": {
                    "name": "Exploitation for Privilege Escalation",
                    "tactic": "Privilege Escalation",
                    "description": "Adversaries may exploit software vulnerabilities to elevate privileges",
                    "detection": ["privilege escalation", "exploit", "elevation"]
                },
                "T1078": {
                    "name": "Valid Accounts",
                    "tactic": "Privilege Escalation",
                    "description": "Adversaries may obtain credentials of higher privileged accounts",
                    "detection": ["admin login", "sudo", "runas"]
                },
                
                # Defense Evasion
                "T1070": {
                    "name": "Indicator Removal",
                    "tactic": "Defense Evasion",
                    "description": "Adversaries may delete or modify artifacts to remove evidence",
                    "detection": ["log deletion", "clear event log", "file deletion"]
                },
                "T1562": {
                    "name": "Impair Defenses",
                    "tactic": "Defense Evasion",
                    "description": "Adversaries may maliciously modify components to impair defenses",
                    "detection": ["disable antivirus", "stop firewall", "disable logging"]
                },
                
                # Credential Access
                "T1110": {
                    "name": "Brute Force",
                    "tactic": "Credential Access",
                    "description": "Adversaries may use brute force techniques to gain access",
                    "detection": ["failed login", "password spray", "brute force"]
                },
                "T1003": {
                    "name": "OS Credential Dumping",
                    "tactic": "Credential Access",
                    "description": "Adversaries may attempt to dump credentials",
                    "detection": ["mimikatz", "lsass", "credential dump"]
                },
                
                # Discovery
                "T1046": {
                    "name": "Network Service Scanning",
                    "tactic": "Discovery",
                    "description": "Adversaries may attempt to get a listing of services running on remote hosts",
                    "detection": ["port scan", "nmap", "service enumeration"]
                },
                "T1018": {
                    "name": "Remote System Discovery",
                    "tactic": "Discovery",
                    "description": "Adversaries may attempt to get a listing of other systems",
                    "detection": ["network enumeration", "ping sweep", "arp scan"]
                },
                "T1087": {
                    "name": "Account Discovery",
                    "tactic": "Discovery",
                    "description": "Adversaries may attempt to get a listing of accounts",
                    "detection": ["user enumeration", "net user", "whoami"]
                },
                
                # Lateral Movement
                "T1021": {
                    "name": "Remote Services",
                    "tactic": "Lateral Movement",
                    "description": "Adversaries may use valid accounts to log into remote services",
                    "detection": ["rdp", "ssh", "smb", "psexec"]
                },
                "T1570": {
                    "name": "Lateral Tool Transfer",
                    "tactic": "Lateral Movement",
                    "description": "Adversaries may transfer tools between systems",
                    "detection": ["file transfer", "copy", "scp"]
                },
                
                # Collection
                "T1005": {
                    "name": "Data from Local System",
                    "tactic": "Collection",
                    "description": "Adversaries may search local system sources to find files of interest",
                    "detection": ["file access", "data collection", "search"]
                },
                "T1560": {
                    "name": "Archive Collected Data",
                    "tactic": "Collection",
                    "description": "Adversaries may compress and/or encrypt data prior to exfiltration",
                    "detection": ["zip", "rar", "compression", "archive"]
                },
                
                # Exfiltration
                "T1041": {
                    "name": "Exfiltration Over C2 Channel",
                    "tactic": "Exfiltration",
                    "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel",
                    "detection": ["data transfer", "outbound connection", "large upload"]
                },
                "T1048": {
                    "name": "Exfiltration Over Alternative Protocol",
                    "tactic": "Exfiltration",
                    "description": "Adversaries may steal data by exfiltrating it over a different protocol",
                    "detection": ["dns exfiltration", "icmp tunnel", "unusual protocol"]
                },
                "T1567": {
                    "name": "Exfiltration Over Web Service",
                    "tactic": "Exfiltration",
                    "description": "Adversaries may use web services to exfiltrate data",
                    "detection": ["cloud upload", "file sharing", "dropbox", "google drive"]
                },
                
                # Impact
                "T1486": {
                    "name": "Data Encrypted for Impact",
                    "tactic": "Impact",
                    "description": "Adversaries may encrypt data to disrupt availability",
                    "detection": ["ransomware", "file encryption", "encrypted files"]
                },
                "T1490": {
                    "name": "Inhibit System Recovery",
                    "tactic": "Impact",
                    "description": "Adversaries may delete or remove built-in data to make recovery more difficult",
                    "detection": ["delete backup", "vssadmin delete", "shadow copy"]
                },
                "T1498": {
                    "name": "Network Denial of Service",
                    "tactic": "Impact",
                    "description": "Adversaries may perform Network DoS attacks",
                    "detection": ["ddos", "syn flood", "udp flood"]
                },
                
                # Reconnaissance
                "T1595": {
                    "name": "Active Scanning",
                    "tactic": "Reconnaissance",
                    "description": "Adversaries may execute active reconnaissance scans",
                    "detection": ["vulnerability scan", "port scan", "network scan"]
                }
            }
        }
        
        # Save for future use
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        return data
    
    def _create_behavior_mappings(self) -> Dict[str, List[str]]:
        """Create mappings from behaviors to techniques"""
        mappings = {}
        
        for technique_id, technique_data in self.techniques.get("techniques", {}).items():
            for detection_pattern in technique_data.get("detection", []):
                if detection_pattern not in mappings:
                    mappings[detection_pattern] = []
                mappings[detection_pattern].append(technique_id)
        
        return mappings
    
    def map_to_techniques(self, description: str, anomaly_type: str = None) -> List[str]:
        """Map event description to MITRE ATT&CK techniques"""
        techniques = set()
        description_lower = description.lower()
        
        # Check behavior mappings
        for pattern, technique_ids in self.behavior_mappings.items():
            if pattern in description_lower:
                techniques.update(technique_ids)
        
        # Anomaly type specific mappings
        if anomaly_type:
            type_mappings = {
                "brute_force_attempt": ["T1110"],
                "port_scanning": ["T1046"],
                "unusual_data_access": ["T1005"],
                "suspicious_process_execution": ["T1059"],
                "lateral_movement": ["T1021", "T1078"],
                "data_exfiltration": ["T1041", "T1048", "T1567"],
                "ransomware": ["T1486", "T1490"]
            }
            if anomaly_type in type_mappings:
                techniques.update(type_mappings[anomaly_type])
        
        return list(techniques)
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Get details for a specific technique"""
        return self.techniques.get("techniques", {}).get(technique_id)
    
    def get_tactics_for_techniques(self, technique_ids: List[str]) -> List[str]:
        """Get tactics for given techniques"""
        tactics = set()
        for tid in technique_ids:
            technique = self.get_technique_details(tid)
            if technique:
                tactics.add(technique.get("tactic", "Unknown"))
        return list(tactics)
