"""
Configuration for Security Platform
"""
import yaml
from pathlib import Path


DEFAULT_CONFIG = {
    # API Settings
    "api": {
        "host": "0.0.0.0",
        "port": 8000,
        "reload": True
    },
    
    # Database
    "database": {
        "path": "security_platform.db"
    },
    
    # SIEM Settings
    "siem": {
        "anomaly_detection": {
            "sensitivity": 0.7,  # 0-1, higher = more sensitive
            "baseline_window_days": 30,
            "min_samples": 100
        },
        "correlation": {
            "time_window_minutes": 60,
            "min_confidence": 0.6
        },
        "alert_classification": {
            "critical_threshold": 90,
            "high_threshold": 70,
            "medium_threshold": 40
        }
    },
    
    # CTI Settings
    "cti": {
        "threat_feeds": {
            "alienvault_otx": {
                "enabled": True,
                "url": "https://otx.alienvault.com/api/v1/",
                "api_key": "YOUR_API_KEY_HERE"
            },
            "abuseipdb": {
                "enabled": True,
                "url": "https://api.abuseipdb.com/api/v2/",
                "api_key": "YOUR_API_KEY_HERE"
            },
            "virustotal": {
                "enabled": False,
                "url": "https://www.virustotal.com/api/v3/",
                "api_key": "YOUR_API_KEY_HERE"
            }
        },
        "enrichment": {
            "geolocation_db": "GeoLite2-City.mmdb",
            "cache_ttl_hours": 24
        },
        "risk_scoring": {
            "weights": {
                "severity": 0.3,
                "prevalence": 0.2,
                "confidence": 0.2,
                "recency": 0.15,
                "targeting": 0.15
            }
        },
        "ioc_retention_days": 90,
        "feed_refresh_hours": 6
    },
    
    # IR Settings
    "incident_response": {
        "auto_containment": {
            "enabled": False,  # Requires approval for safety
            "severity_threshold": "Critical"
        },
        "forensics": {
            "evidence_path": "./forensic_evidence",
            "auto_collect": True
        },
        "notification": {
            "email_enabled": False,
            "slack_webhook": None,
            "teams_webhook": None
        }
    },
    
    # MITRE ATT&CK
    "mitre": {
        "data_file": "mitre_attack_data.json",
        "auto_update": True,
        "update_interval_days": 7
    }
}


class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        """Load configuration from file or use defaults"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge with defaults
                return self._merge_configs(DEFAULT_CONFIG, user_config)
        else:
            # Create default config file
            self.save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()
    
    def _merge_configs(self, default: dict, user: dict) -> dict:
        """Recursively merge user config with defaults"""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def save_config(self, config: dict = None):
        """Save configuration to file"""
        config_to_save = config or self.config
        with open(self.config_path, 'w') as f:
            yaml.dump(config_to_save, f, default_flow_style=False, indent=2)
    
    def get(self, key_path: str, default=None):
        """Get config value by dot-separated path"""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value


# Global config instance
config = Config()
