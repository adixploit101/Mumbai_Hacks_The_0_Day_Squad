"""
Log Ingestion Engine
Multi-source log parsing and normalization
"""
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional
from models import LogEvent, LogSource


class LogIngestionEngine:
    """Parse and normalize logs from multiple sources"""
    
    def __init__(self):
        self.parsers = {
            LogSource.FIREWALL: self.parse_firewall_log,
            LogSource.SERVER: self.parse_server_log,
            LogSource.CLOUD: self.parse_cloud_log,
            LogSource.ENDPOINT: self.parse_endpoint_log,
            LogSource.IDS_IPS: self.parse_ids_log
        }
    
    def ingest_log(self, raw_log: str, source: LogSource) -> LogEvent:
        """Ingest and normalize a single log"""
        parser = self.parsers.get(source, self.parse_generic_log)
        return parser(raw_log, source)
    
    def parse_firewall_log(self, raw_log: str, source: LogSource) -> LogEvent:
        """Parse firewall logs (Cisco ASA, Palo Alto, pfSense)"""
        # Example: "2025-11-28 23:00:00 src=192.168.1.100 dst=10.0.0.50 action=deny proto=tcp sport=45123 dport=22"
        timestamp = datetime.utcnow()
        data = {}
        
        # Extract timestamp if present
        ts_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', raw_log)
        if ts_match:
            timestamp = datetime.fromisoformat(ts_match.group(1))
        
        # Extract key-value pairs
        kv_pattern = r'(\w+)=([^\s]+)'
        for match in re.finditer(kv_pattern, raw_log):
            data[match.group(1)] = match.group(2)
        
        return LogEvent(
            timestamp=timestamp,
            source=source,
            source_ip=data.get('src'),
            dest_ip=data.get('dst'),
            source_port=int(data.get('sport', 0)) if data.get('sport') else None,
            dest_port=int(data.get('dport', 0)) if data.get('dport') else None,
            protocol=data.get('proto'),
            action=data.get('action'),
            message=f"Firewall {data.get('action', 'event')}: {data.get('src', 'unknown')} -> {data.get('dst', 'unknown')}",
            raw_log=raw_log,
            metadata=data
        )
    
    def parse_server_log(self, raw_log: str, source: LogSource) -> LogEvent:
        """Parse server logs (Windows Event, Syslog, Apache/Nginx)"""
        timestamp = datetime.utcnow()
        data = {}
        
        # Try to parse as JSON first
        try:
            data = json.loads(raw_log)
            timestamp = datetime.fromisoformat(data.get('timestamp', datetime.utcnow().isoformat()))
            
            return LogEvent(
                timestamp=timestamp,
                source=source,
                user=data.get('user'),
                hostname=data.get('hostname'),
                process=data.get('process'),
                action=data.get('action'),
                message=data.get('message', raw_log),
                raw_log=raw_log,
                metadata=data
            )
        except json.JSONDecodeError:
            # Parse syslog format
            # Example: "Nov 28 23:00:00 server1 sshd[1234]: Failed password for admin from 192.168.1.100"
            syslog_match = re.match(
                r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)',
                raw_log
            )
            
            if syslog_match:
                hostname = syslog_match.group(2)
                process = syslog_match.group(3)
                message = syslog_match.group(5)
                
                # Extract IP if present
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                source_ip = ip_match.group(1) if ip_match else None
                
                # Extract user if present
                user_match = re.search(r'(?:for|user)\s+(\w+)', message)
                user = user_match.group(1) if user_match else None
                
                return LogEvent(
                    timestamp=timestamp,
                    source=source,
                    hostname=hostname,
                    process=process,
                    user=user,
                    source_ip=source_ip,
                    message=message,
                    raw_log=raw_log,
                    metadata={'process': process, 'hostname': hostname}
                )
            
            return self.parse_generic_log(raw_log, source)
    
    def parse_cloud_log(self, raw_log: str, source: LogSource) -> LogEvent:
        """Parse cloud logs (AWS CloudTrail, Azure Activity, GCP Audit)"""
        try:
            data = json.loads(raw_log)
            
            # AWS CloudTrail format
            if 'eventName' in data:
                return LogEvent(
                    timestamp=datetime.fromisoformat(data.get('eventTime', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                    source=source,
                    user=data.get('userIdentity', {}).get('userName'),
                    source_ip=data.get('sourceIPAddress'),
                    action=data.get('eventName'),
                    message=f"AWS {data.get('eventName')}: {data.get('eventSource')}",
                    raw_log=raw_log,
                    metadata=data
                )
            
            # Generic cloud log
            return LogEvent(
                timestamp=datetime.fromisoformat(data.get('timestamp', datetime.utcnow().isoformat())),
                source=source,
                user=data.get('user'),
                action=data.get('action') or data.get('operation'),
                message=data.get('message', str(data)),
                raw_log=raw_log,
                metadata=data
            )
        except json.JSONDecodeError:
            return self.parse_generic_log(raw_log, source)
    
    def parse_endpoint_log(self, raw_log: str, source: LogSource) -> LogEvent:
        """Parse endpoint logs (EDR, antivirus, system events)"""
        try:
            data = json.loads(raw_log)
            
            return LogEvent(
                timestamp=datetime.fromisoformat(data.get('timestamp', datetime.utcnow().isoformat())),
                source=source,
                hostname=data.get('hostname'),
                user=data.get('user'),
                process=data.get('process'),
                action=data.get('action'),
                message=data.get('message', f"Endpoint event: {data.get('action', 'unknown')}"),
                raw_log=raw_log,
                metadata=data
            )
        except json.JSONDecodeError:
            return self.parse_generic_log(raw_log, source)
    
    def parse_ids_log(self, raw_log: str, source: LogSource) -> LogEvent:
        """Parse IDS/IPS logs (Snort, Suricata, Zeek)"""
        try:
            data = json.loads(raw_log)
            
            return LogEvent(
                timestamp=datetime.fromisoformat(data.get('timestamp', datetime.utcnow().isoformat())),
                source=source,
                source_ip=data.get('src_ip'),
                dest_ip=data.get('dest_ip'),
                source_port=data.get('src_port'),
                dest_port=data.get('dest_port'),
                protocol=data.get('proto'),
                action=data.get('action', 'alert'),
                message=data.get('alert', {}).get('signature', data.get('message', 'IDS Alert')),
                raw_log=raw_log,
                metadata=data
            )
        except json.JSONDecodeError:
            # Parse Snort alert format
            # Example: "[**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**]"
            return LogEvent(
                timestamp=datetime.utcnow(),
                source=source,
                message=raw_log,
                raw_log=raw_log,
                metadata={}
            )
    
    def parse_generic_log(self, raw_log: str, source: LogSource) -> LogEvent:
        """Generic log parser for unknown formats"""
        return LogEvent(
            timestamp=datetime.utcnow(),
            source=source,
            message=raw_log[:200],  # Truncate long messages
            raw_log=raw_log,
            metadata={}
        )
    
    def ingest_batch(self, logs: list, source: LogSource) -> list[LogEvent]:
        """Ingest multiple logs"""
        return [self.ingest_log(log, source) for log in logs]
