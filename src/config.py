# src/config.py
from pydantic import BaseSettings, AnyUrl, Field
from typing import Dict, Tuple

class Settings(BaseSettings):
    redis_uri: AnyUrl = Field(default="redis://localhost:6379/0", )
    suricata_rule_file: str = Field(default="/usr/local/cti-suricata/rules/cti.rules")
    suricata_pid_file: str = Field(default="/var/run/suricata/suricata.pid")
    threat_log_file: str = Field(default="/var/log/cti-suricata/threat.log",)
    rule_ttl: int = Field(default=86400, env="RULE_TTL")
    

    exec_start_pre_mkdir: str = "/bin/mkdir -p /var/run/suricata"
    exec_start_pre_chown: str = "/bin/chown suricata:suricata /var/run/suricata"



    class Config:
        
        env_file_encoding = "utf-8"

settings = Settings()

stix_mapping: Dict[str, Tuple[str, str]] = {
    'domain-name': ('value', 'domain'),
    'ipv4-addr': ('value', 'ip'),
    'ipv6-addr': ('value', 'ip'),
    'url': ('value', 'url'),
    'file': ('hashes', 'hash'),
    'email-addr': ('value', 'email'),
    'mac-addr': ('value', 'mac'),
    'indicator': ('pattern', 'parse'),
    'observed-data': ('objects', 'parse')
}

channel_to_stix = {
    f"{stix_type}Created": stix_type  
    for stix_type in stix_mapping.keys()
}