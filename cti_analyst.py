"""
Cyber Threat Intelligence (CTI) Analyst
IOC enrichment, threat detection, and risk scoring
"""
import re
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from models import IOC, ThreatIntel, IOCType, ThreatCategory, ThreatActor, Campaign
from database import SecurityDatabase


class CTIAnalyst:
    """Cyber Threat Intelligence analysis and enrichment"""
    
    def __init__(self, db: SecurityDatabase):
        self.db = db
        self.threat_feeds = self._load_threat_feeds()
        self.threat_actors_db = self._load_threat_actors()
    
    def _load_threat_feeds(self) -> Dict:
        """Load threat intelligence feeds (simulated)"""
        return {
            "malicious_ips": set([
                "45.142.212.61", "185.220.101.1", "23.129.64.131",
                "91.219.236.197", "104.244.72.115"
            ]),
            "c2_domains": set([
                "evil-c2.com", "malware-command.net", "botnet-control.org",
                "phishing-kit.xyz", "ransomware-c2.ru"
            ]),
            "malware_hashes": {
                "44d88612fea8a8f36de82e1278abb02f": "Emotet",
                "5f4dcc3b5aa765d61d8327deb882cf99": "TrickBot",
                "098f6bcd4621d373cade4e832627b4f6": "Ryuk"
            }
        }
    
    def _load_threat_actors(self) -> Dict[str, ThreatActor]:
        """Load known threat actor profiles"""
        return {
            "APT28": ThreatActor(
                id="APT28",
                name="APT28",
                aliases=["Fancy Bear", "Sofacy", "Sednit"],
                description="Russian state-sponsored threat group",
                origin_country="Russia",
                motivation=["espionage", "political"],
                target_industries=["government", "military", "media"],
                target_regions=["Europe", "North America"],
                ttps=["T1566", "T1078", "T1021", "T1003"],
                known_tools=["X-Agent", "Sofacy", "Komplex"]
            ),
            "Lazarus Group": ThreatActor(
                id="Lazarus",
                name="Lazarus Group",
                aliases=["Hidden Cobra", "Guardians of Peace"],
                description="North Korean state-sponsored threat group",
                origin_country="North Korea",
                motivation=["financial", "espionage"],
                target_industries=["financial", "cryptocurrency", "media"],
                target_regions=["Global"],
                ttps=["T1486", "T1566", "T1059", "T1105"],
                known_tools=["WannaCry", "HOPLIGHT", "BLINDINGCAN"]
            ),
            "FIN7": ThreatActor(
                id="FIN7",
                name="FIN7",
                aliases=["Carbanak Group"],
                description="Financially motivated cybercrime group",
                origin_country="Unknown",
                motivation=["financial"],
                target_industries=["retail", "hospitality", "financial"],
                target_regions=["North America", "Europe"],
                ttps=["T1566", "T1059", "T1003", "T1041"],
                known_tools=["Carbanak", "GRIFFON", "POWERSOURCE"]
            )
        }
    
    def enrich_ioc(self, indicator: str, ioc_type: IOCType) -> ThreatIntel:
        """Enrich IOC with threat intelligence"""
        # Create base IOC
        ioc = IOC(
            indicator=indicator,
            ioc_type=ioc_type,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            source="internal_detection"
        )
        
        # Enrich based on type
        if ioc_type == IOCType.IP:
            return self._enrich_ip(ioc)
        elif ioc_type in [IOCType.DOMAIN, IOCType.URL]:
            return self._enrich_domain(ioc)
        elif ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
            return self._enrich_hash(ioc)
        else:
            return self._create_basic_intel(ioc)
    
    def _enrich_ip(self, ioc: IOC) -> ThreatIntel:
        """Enrich IP address"""
        ip = ioc.indicator
        
        # Check against threat feeds
        is_malicious = ip in self.threat_feeds["malicious_ips"]
        
        # Simulate geolocation (in production, use MaxMind GeoIP2)
        geolocation = self._get_geolocation(ip)
        
        # Simulate ASN lookup
        asn, asn_org = self._get_asn(ip)
        
        # Determine threat category
        threat_category = ThreatCategory.C2 if is_malicious else None
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            is_malicious=is_malicious,
            threat_category=threat_category,
            geolocation=geolocation
        )
        
        intel = ThreatIntel(
            ioc_id=ioc.id,
            indicator=ip,
            ioc_type=ioc.ioc_type,
            geolocation=geolocation,
            asn=asn,
            asn_org=asn_org,
            threat_category=threat_category,
            risk_score=risk_score,
            confidence=0.85 if is_malicious else 0.3,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen
        )
        
        if is_malicious:
            intel.malware_families = ["Generic Malware"]
            intel.campaigns = ["Botnet Campaign 2025"]
        
        return intel
    
    def _enrich_domain(self, ioc: IOC) -> ThreatIntel:
        """Enrich domain/URL"""
        domain = ioc.indicator
        
        # Check against C2 domains
        is_c2 = domain in self.threat_feeds["c2_domains"]
        
        # Check for phishing indicators
        is_phishing = self._detect_phishing(domain)
        
        threat_category = None
        if is_c2:
            threat_category = ThreatCategory.C2
        elif is_phishing:
            threat_category = ThreatCategory.PHISHING
        
        risk_score = self._calculate_risk_score(
            is_malicious=is_c2 or is_phishing,
            threat_category=threat_category
        )
        
        intel = ThreatIntel(
            ioc_id=ioc.id,
            indicator=domain,
            ioc_type=ioc.ioc_type,
            threat_category=threat_category,
            risk_score=risk_score,
            confidence=0.9 if (is_c2 or is_phishing) else 0.2,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen
        )
        
        if is_c2:
            intel.malware_families = ["Botnet"]
            intel.threat_actors = ["Unknown APT"]
        
        return intel
    
    def _enrich_hash(self, ioc: IOC) -> ThreatIntel:
        """Enrich file hash"""
        file_hash = ioc.indicator
        
        # Check against malware database
        malware_family = self.threat_feeds["malware_hashes"].get(file_hash)
        
        threat_category = ThreatCategory.MALWARE if malware_family else None
        if malware_family and "Ryuk" in malware_family:
            threat_category = ThreatCategory.RANSOMWARE
        
        risk_score = self._calculate_risk_score(
            is_malicious=malware_family is not None,
            threat_category=threat_category
        )
        
        intel = ThreatIntel(
            ioc_id=ioc.id,
            indicator=file_hash,
            ioc_type=ioc.ioc_type,
            malware_families=[malware_family] if malware_family else [],
            threat_category=threat_category,
            risk_score=risk_score,
            confidence=0.95 if malware_family else 0.1,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen
        )
        
        return intel
    
    def _create_basic_intel(self, ioc: IOC) -> ThreatIntel:
        """Create basic threat intel for unknown IOC"""
        return ThreatIntel(
            ioc_id=ioc.id,
            indicator=ioc.indicator,
            ioc_type=ioc.ioc_type,
            risk_score=10,
            confidence=0.1,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen
        )
    
    def _get_geolocation(self, ip: str) -> Dict:
        """Simulate geolocation lookup"""
        # In production, use MaxMind GeoIP2
        return {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0
        }
    
    def _get_asn(self, ip: str) -> tuple:
        """Simulate ASN lookup"""
        # In production, use Team Cymru or similar
        return ("AS12345", "Unknown ISP")
    
    def _detect_phishing(self, domain: str) -> bool:
        """Detect phishing indicators in domain"""
        phishing_keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm']
        suspicious_tlds = ['.xyz', '.top', '.club', '.work']
        
        domain_lower = domain.lower()
        
        # Check for suspicious keywords + TLD combination
        has_keyword = any(kw in domain_lower for kw in phishing_keywords)
        has_suspicious_tld = any(domain_lower.endswith(tld) for tld in suspicious_tlds)
        
        return has_keyword and has_suspicious_tld
    
    def _calculate_risk_score(self, is_malicious: bool, threat_category: Optional[ThreatCategory] = None, 
                              geolocation: Optional[Dict] = None) -> float:
        """Calculate risk score (0-100)"""
        score = 0.0
        
        if is_malicious:
            score += 60
        
        if threat_category:
            category_scores = {
                ThreatCategory.APT: 95,
                ThreatCategory.RANSOMWARE: 95,
                ThreatCategory.C2: 85,
                ThreatCategory.MALWARE: 75,
                ThreatCategory.PHISHING: 70,
                ThreatCategory.BOTNET: 65
            }
            score = max(score, category_scores.get(threat_category, 50))
        
        # Adjust based on geolocation (high-risk countries)
        if geolocation and geolocation.get("country") in ["Unknown", "Russia", "China", "North Korea"]:
            score += 10
        
        return min(score, 100)
    
    def correlate_threat_actor(self, iocs: List[str], ttps: List[str]) -> Optional[ThreatActor]:
        """Correlate IOCs and TTPs with known threat actors"""
        best_match = None
        best_score = 0
        
        for actor_id, actor in self.threat_actors_db.items():
            score = 0
            
            # Check TTP overlap
            ttp_overlap = len(set(ttps) & set(actor.ttps))
            score += ttp_overlap * 20
            
            # In production, check IOC overlap with known actor infrastructure
            
            if score > best_score:
                best_score = score
                best_match = actor
        
        return best_match if best_score > 40 else None
    
    def get_active_campaigns(self) -> List[Campaign]:
        """Get active threat campaigns"""
        # In production, query from threat intel feeds
        return [
            Campaign(
                name="Ransomware Campaign Q4 2025",
                description="Widespread ransomware campaign targeting healthcare and education sectors",
                threat_actors=["Lazarus"],
                start_date=datetime.utcnow() - timedelta(days=30),
                is_active=True,
                target_industries=["healthcare", "education"],
                ttps=["T1486", "T1490", "T1566"],
                severity="Critical"
            )
        ]
