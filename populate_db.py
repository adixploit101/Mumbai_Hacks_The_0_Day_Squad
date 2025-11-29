"""
Populate database with sample alerts for testing
"""
import sqlite3
import uuid
import json
import random
from datetime import datetime, timedelta, timezone

# Connect to database
conn = sqlite3.connect('security_platform.db')
cursor = conn.cursor()

# Sample data
severities = ['Critical', 'High', 'Medium', 'Low']
incident_types = ['Malware', 'Phishing', 'Unauthorized Access', 'Data Breach', 'DDoS Attack']
ips = [f"192.168.1.{random.randint(1, 255)}" for _ in range(10)]
ips.extend([f"10.0.0.{random.randint(1, 255)}" for _ in range(5)])

titles = [
    "Suspicious Login Attempt Detected",
    "Malware Signature Match",
    "Unusual Outbound Traffic",
    "Brute Force Attack Detected",
    "Privilege Escalation Attempt",
    "Data Exfiltration Detected",
    "Phishing Email Blocked",
    "Unauthorized Access Attempt",
    "SQL Injection Attempt",
    "Cross-Site Scripting Detected",
    "Port Scan Detected",
    "Ransomware Activity",
    "Credential Theft Attempt",
    "Lateral Movement Detected",
    "Command and Control Communication"
]

print("Creating sample alerts...")

# Clear existing alerts to avoid duplicates if running multiple times (optional, but good for testing)
# cursor.execute("DELETE FROM alerts") 

for i in range(25):
    alert_id = str(uuid.uuid4())
    timestamp = (datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 72))).isoformat()
    severity = random.choice(severities)
    incident_type = random.choice(incident_types)
    ip = random.choice(ips)
    title = random.choice(titles)
    description = f"Detected {incident_type.lower()} activity from IP {ip}. Immediate investigation required."
    affected_assets = json.dumps([f"server-{random.randint(1, 15)}", f"workstation-{random.randint(1, 50)}"])
    mitre_techniques = json.dumps([f"T{random.randint(1000, 1600)}"])
    confidence_score = round(random.uniform(0.65, 0.98), 2)
    is_false_positive = 0 if random.random() > 0.1 else 1
    explanation = "Automated detection based on signature match and behavioral analysis."

    cursor.execute('''
        INSERT INTO alerts (
            id, timestamp, severity, title, description, affected_assets,
            mitre_techniques, confidence_score, is_false_positive, explanation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        alert_id, timestamp, severity, f"{title} #{i+1}", description, affected_assets,
        mitre_techniques, confidence_score, is_false_positive, explanation
    ))

conn.commit()
print(f"✓ Created 25 sample alerts")
print("Database populated successfully!")
conn.close()
