"""
Populate database with a LARGE dataset of sample alerts for testing
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
incident_types = ['Malware', 'Phishing', 'Unauthorized Access', 'Data Breach', 'DDoS Attack', 'Insider Threat', 'Ransomware', 'Social Engineering']
sources = ['SIEM', 'IDS', 'Firewall', 'EDR', 'Network Monitor', 'CloudWatch', 'Azure Sentinel', 'CrowdStrike']

# Generate realistic IPs
ips = [f"192.168.1.{random.randint(1, 255)}" for _ in range(20)]
ips.extend([f"10.0.0.{random.randint(1, 255)}" for _ in range(10)])
ips.extend([f"172.16.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(10)])
public_ips = [f"{random.randint(1, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(15)]
ips.extend(public_ips)

titles_map = {
    'Malware': ["Trojan.Win32.Emotet Detected", "Ransomware.Ryuk Activity", "Suspicious PowerShell Execution", "Malicious File Download Blocked"],
    'Phishing': ["Suspicious Email Reported", "Phishing Link Clicked", "Credential Harvesting Page Detected", "Spear Phishing Attempt"],
    'Unauthorized Access': ["Brute Force Login Attempt", "Impossible Travel Login", "Login from Unusual Location", "Failed Login Spike"],
    'Data Breach': ["Sensitive Data Exfiltration", "Large Outbound Transfer", "Database Dump Detected", "PII Pattern Match"],
    'DDoS Attack': ["High Volume UDP Traffic", "SYN Flood Detected", "HTTP Flood Targeting Web Server", "Slowloris Attack"],
    'Insider Threat': ["Privilege Escalation Attempt", "Access to Restricted Folder", "After-Hours Activity", "USB Device Inserted"],
    'Ransomware': ["File Encryption Activity", "Shadow Copy Deletion Attempt", "Ransom Note File Created", "High Disk I/O Detected"],
    'Social Engineering': ["BEC Attempt Detected", "Fake Tech Support Activity", "Social Media Impersonation", "Vishing Report"]
}

print("Creating large dataset of sample alerts...")

# Clear existing alerts
cursor.execute("DELETE FROM alerts") 

# Generate 150 alerts over the last 7 days
for i in range(150):
    alert_id = str(uuid.uuid4())
    
    # Weighted random for severity (fewer criticals)
    severity = random.choices(severities, weights=[10, 20, 40, 30], k=1)[0]
    
    incident_type = random.choice(incident_types)
    title = random.choice(titles_map.get(incident_type, ["Security Alert"]))
    ip = random.choice(ips)
    source = random.choice(sources)
    
    # Spread timestamps over last 7 days
    days_ago = random.randint(0, 7)
    hours_ago = random.randint(0, 23)
    minutes_ago = random.randint(0, 59)
    timestamp = (datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)).isoformat()
    
    description = f"Detected {incident_type.lower()} activity from source {ip} via {source}. Analysis indicates potential security violation."
    
    affected_assets = json.dumps([f"server-{random.randint(1, 20)}", f"workstation-{random.randint(1, 100)}"])
    mitre_techniques = json.dumps([f"T{random.randint(1000, 1600)}", f"T{random.randint(1000, 1600)}"])
    
    confidence_score = round(random.uniform(0.60, 0.99), 2)
    is_false_positive = 0 if random.random() > 0.15 else 1
    explanation = "Automated detection based on signature match, behavioral analysis, and threat intelligence correlation."

    cursor.execute('''
        INSERT INTO alerts (
            id, timestamp, severity, title, description, affected_assets,
            mitre_techniques, confidence_score, is_false_positive, explanation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        alert_id, timestamp, severity, f"{title}", description, affected_assets,
        mitre_techniques, confidence_score, is_false_positive, explanation
    ))

# Generate Incidents
print("Generating incidents...")
cursor.execute("DELETE FROM incidents")
statuses = ['open', 'investigating', 'contained', 'resolved']
for i in range(20):
    incident_id = str(uuid.uuid4())
    severity = random.choice(['Critical', 'High'])
    status = random.choice(statuses)
    incident_type = random.choice(incident_types)
    
    cursor.execute('''
        INSERT INTO incidents (
            id, timestamp, incident_type, severity, title, description,
            confidence_score, status, affected_assets, attack_path,
            mitre_tactics, mitre_techniques, recommended_actions
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        incident_id, datetime.now(timezone.utc).isoformat(), incident_type, severity,
        f"{incident_type} Incident #{i+1}", "Automated incident creation",
        0.95, status, json.dumps(["asset-1", "asset-2"]), json.dumps(["recon", "exploit"]),
        json.dumps(["Initial Access"]), json.dumps(["T1000"]), json.dumps(["Isolate"])
    ))

# Generate Campaigns
print("Generating campaigns...")
cursor.execute("DELETE FROM campaigns")
campaigns = [
    ("APT29 Cozy Bear", "State-sponsored espionage campaign targeting government agencies"),
    ("Lazarus Group", "Financial theft and espionage operations"),
    ("Wizard Spider", "Ransomware campaigns targeting healthcare and finance")
]

for name, desc in campaigns:
    cursor.execute('''
        INSERT INTO campaigns (id, name, description, is_active, severity, target_industries)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (str(uuid.uuid4()), name, desc, 1, 'Critical', json.dumps(['Finance', 'Healthcare'])))

conn.commit()
print(f"✓ Created 150 sample alerts, 20 incidents, and 3 active campaigns")
print("Database populated successfully!")
conn.close()
