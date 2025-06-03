import re
import logging
from typing import List, Dict
from stix2 import parse

class STIXProcessor:
    def __init__(self):
        self.logger = logging.getLogger("stix")
        self.pattern_parser = re.compile(
            r"\[([a-z\-]+):([a-z\-_]+)\s*=\s*'([^']+)'\]",
            re.IGNORECASE
        )
        self.validators = {
            'domain': r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$",
            'ip': r"^(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})$",
            'url': r"^https?://",
            'hash': r"^[a-fA-F0-9]{32,64}$",  # Supports MD5 (32), SHA-1 (40), SHA-256 (64)
            'email': r"^[\w\.-]+@[\w\.-]+\.\w+$",
            'mac': r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        }

    def validate_observable(self, obs_type: str, value: str) -> bool:
        if obs_type == 'hash':
            # Validate MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars)
            if len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value):
                return True
            return False
        validator = self.validators.get(obs_type, r".*")
        return bool(re.match(validator, value)) if isinstance(value, str) else False

    def parse_indicator(self, pattern: str) -> List[Dict[str, str]]:
        self.logger.debug(f"Parsing indicator pattern: {pattern}")
        observables = []
        for match in self.pattern_parser.findall(pattern):
            try:
                stix_type, _, value = match
                obs_type = stix_type.split(':')[0].replace('-', ' ')
                mapped_type = None
                if stix_type.startswith('file:hashes.'):
                    if 'SHA-256' in stix_type or 'SHA-1' in stix_type or 'MD5' in stix_type:
                        mapped_type = 'hash'
                        value = value.upper()
                else:
                    type_map = {
                        'ipv4-addr': 'ip',
                        'ipv6-addr': 'ip',
                        'domain-name': 'domain',
                        'url': 'url',
                        'email-addr': 'email',
                        'mac-addr': 'mac'
                    }
                    mapped_type = type_map.get(obs_type, obs_type)
                if mapped_type and self.validate_observable(mapped_type, value):
                    observables.append({"type": mapped_type, "value": value})
            except Exception as e:
                self.logger.warning(f"Pattern segment error: {str(e)}")
        return observables

    # In stix_processor.py
    def parse_observed_data(self, objects: dict) -> List[Dict[str, str]]:
        observables = []
        for obj in objects.values():
            if obj.get('type') == 'file':
                hashes = obj.get('hashes', {})
                for algo in ['SHA-256', 'SHA-1', 'MD5']:
                    if hash_value := hashes.get(algo):
                        observables.append({
                            "type": "hash",
                            "value": hash_value.upper(),
                            "hash_type": algo.lower()
                        })
                        break  
        return observables
