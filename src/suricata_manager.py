# src/suricata_manager.py
import os
import logging
import subprocess
import hashlib
import asyncio
import time
import redis
import re
import tempfile
from typing import List, Tuple, Optional
from .config import settings


class SuricataManager:
    def __init__(self, redis_client: redis.Redis):
        self.logger = logging.getLogger("suricata")
        self.rule_file = settings.suricata_rule_file
        self.pid_file = settings.suricata_pid_file
        self.redis = redis_client
        self.sid_counter = int(self.redis.get("cti:last_sid") or 1000000)
        self.rule_cache_key = "suricata:cti:rules"
        self.rate_limiter = asyncio.Semaphore(5)
        self.last_reload = 0
        self.write_lock = asyncio.Lock()
        self._init_temp_dir()
        self._init_hash_dir()
        self._validate_suricata_installation()
        self._check_suricata_config()

    def _init_temp_dir(self):
        self.temp_dir = "/tmp/suricata_validation"
        os.makedirs(self.temp_dir, exist_ok=True, mode=0o755)

    def _init_hash_dir(self):
        self.hash_dir = "/etc/suricata/hashfiles"
        try:
            os.makedirs(self.hash_dir, exist_ok=True, mode=0o755)
            subprocess.run(["chown", "suricata:suricata", self.hash_dir], check=True)
            subprocess.run(["chmod", "755", self.hash_dir], check=True)
            self.logger.debug(f"Initialized hash directory: {self.hash_dir}")
        except Exception as e:
            self.logger.error(
                f"Failed to initialize hash directory {self.hash_dir}: {e}"
            )
            raise RuntimeError("Hash directory initialization failed")

    def _validate_suricata_installation(self):
        try:
            result = subprocess.run(
                ["suricata", "-V"], capture_output=True, text=True, check=True
            )
            self.logger.info(f"Suricata version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.error("Suricata not found or not functional")
            raise RuntimeError("Suricata installation verification failed")

    def _check_suricata_config(self):
        try:
            result = subprocess.run(
                ["suricata", "--build-info"], capture_output=True, text=True, check=True
            )
            if "libmagic" not in result.stdout.lower():
                self.logger.warning(
                    "Suricata build info does not list libmagic support, file hash rules may fail"
                )
            else:
                self.logger.info("Suricata has libmagic support")
            config_file = "/etc/suricata/suricata.yaml"
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    config = f.read()
                if "dns:" not in config or "enabled: yes" not in config:
                    self.logger.warning(
                        "DNS parser may be disabled, domain rules may fail"
                    )
                if "http:" not in config or "enabled: yes" not in config:
                    self.logger.warning(
                        "HTTP parser may be disabled, URL rules may fail"
                    )
            else:
                self.logger.error(f"Suricata config file {config_file} not found")
            # Check hash file accessibility
            hash_file = f"{self.hash_dir}/cti_hashes.sha256"
            if os.path.exists(hash_file):
                if os.access(hash_file, os.R_OK):
                    self.logger.debug(f"Hash file {hash_file} is readable")
                else:
                    self.logger.error(
                        f"Hash file {hash_file} is not readable by this process"
                    )
            else:
                self.logger.debug(
                    f"Hash file {hash_file} does not yet exist, will be created as needed"
                )
        except Exception as e:
            self.logger.error(f"Failed to check Suricata config: {e}")

    def generate_rule(self, obs_type: str, value: str) -> Optional[Tuple[str, str]]:
        self.logger.debug(f"Generating rule with obs_type={obs_type}, value={value}")
        try:
            value = value.strip()
            if not value:
                self.logger.warning(f"Empty value for obs_type={obs_type}")
                return None

            if obs_type == "hash":
                value = value.lower()
                if not re.fullmatch(r"^[a-f0-9]{32,64}$", value):
                    self.logger.warning(f"Invalid hash format: {value}")
                    return None

            cache_key = f"{obs_type}:{value}"
            rule_hash = hashlib.sha256(cache_key.encode()).hexdigest()
            if self.redis.exists(f"{self.rule_cache_key}:{rule_hash}"):
                self.logger.debug(f"Rule exists in cache: {cache_key}")
                return None

            sid = self.sid_counter
            self.sid_counter += 1
            rule = self._create_rule(obs_type, value, sid)
            if rule:
                self.logger.info(f"Generated rule for {obs_type}: {rule}")
            else:
                self.logger.warning(
                    f"Failed to create rule for obs_type={obs_type}, value={value}"
                )
            return (rule, rule_hash) if rule else None

        except Exception as e:
            self.logger.error(f"Rule generation failed: {e}")
            return None

    def _create_rule(self, obs_type: str, value: str, sid: int) -> Optional[str]:
        templates = {
            "ip": lambda v, s: f'drop ip {v} any -> any any (msg:"CTI: Malicious IP {v}"; sid:{s}; rev:1;)',
            "domain": lambda v, s: (
                f'alert dns any any -> any 53 (msg:"CTI: Malicious Domain {v}"; '
                f'dns_query; content:"{v}"; nocase; sid:{s}; rev:1;)'
            ),
            "hash": lambda v, s: self._create_hash_rule(v, s),
            "email": lambda v, s: (
                f'alert smtp any any -> any any (msg:"CTI: Malicious Email {v}"; '
                f'smtp.to; content:"{v}"; nocase; sid:{s}; rev:1;)'
            ),
            "mac": lambda v, s: (
                f'alert ethernet any any -> any any (msg:"CTI: Malicious MAC {v}"; '
                f"ether dst {v}; sid:{s}; rev:1;)"
            ),
            "url": lambda v, s: self._create_url_rule(v, s),
        }
        if obs_type not in templates:
            self.logger.warning(f"Unsupported type: {obs_type}")
            return None
        return templates[obs_type](value, sid)

    def _create_url_rule(self, value: str, sid: int) -> str:
        clean = value.split("://")[-1]
        host, _, path = clean.partition("/")
        path = f"/{path}" if path else "/"
        rule = (
            f'alert http any any -> any any (msg:"CTI: Malicious URL {value}"; '
            f'content:"{host}"; http_host; '
            f'content:"{path}"; http_uri; nocase; '
            f"sid:{sid}; rev:1;)"
        )
        self.logger.debug(f"Created URL rule: {rule}")
        return rule

    def _create_hash_rule(self, value: str, sid: int) -> Optional[str]:
        mapping = {32: "md5", 40: "sha1", 64: "sha256"}
        ht = mapping.get(len(value))
        if not ht:
            self.logger.warning(f"Invalid hash length: {len(value)} for value: {value}")
            return None

        hash_file = f"{self.hash_dir}/cti_hashes.{ht}"
        try:
            with open(hash_file, "a") as f:
                f.write(value + "\n")
            self.logger.debug(f"Appended hash {value} to {hash_file}")
            # Ensure file is readable by Suricata
            subprocess.run(["chown", "suricata:suricata", hash_file], check=True)
            subprocess.run(["chmod", "644", hash_file], check=True)
        except Exception as e:
            self.logger.error(f"Failed to write hash to {hash_file}: {e}")
            return None

        rule = (
            f'alert http any any -> any any (msg:"CTI: Malicious File {ht.upper()} {value}"; '
            f"file{ht}:{hash_file}; sid:{sid}; rev:1; flow:to_client;)"
        )
        self.logger.debug(f"Created file rule: {rule}")
        return rule

    async def update_rules(self, rules: List[Tuple[str, str]]):
        async with self.rate_limiter:
            try:
                validated = []
                for rule, rule_hash in rules:
                    validated_rule = await asyncio.get_event_loop().run_in_executor(
                        None, self._validate_rule, rule
                    )
                    if validated_rule:
                        validated.append((validated_rule, rule_hash))
                        self.logger.info(f"Validated rule: {validated_rule}")
                    else:
                        self.logger.error(f"Rule validation failed for: {rule}")
                if not validated:
                    self.logger.error(
                        "No rules passed validation. No changes will be applied."
                    )
                    return
                self.logger.info(f"Validated {len(validated)} rules successfully.")
                await self._write_rules([r[0] for r in validated])
                self.logger.info("Rules written to file successfully.")
                await self.reload_suricata()
                self.logger.info("Suricata reloaded successfully.")
                self.redis.set("cti:last_sid", self.sid_counter)
                for _, rule_hash in validated:
                    self.redis.set(
                        f"{self.rule_cache_key}:{rule_hash}",
                        "1",
                        ex=3600 * 24 * 7,
                    )
                self.last_reload = time.time()
            except Exception as e:
                self.logger.error(f"Rule update failed: {e}")
                raise

    def _validate_rule(self, rule: str) -> Optional[str]:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, dir=self.temp_dir
            ) as tmp:
                tmp.write(rule + "\n")
                tmp_path = tmp.name
            self.logger.debug(f"Validating rule: {rule}")
            result = subprocess.run(
                [
                    "suricata",
                    "-T",
                    "-S",
                    tmp_path,
                    "--set",
                    "default-log-dir=/var/log/suricata",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                self.logger.debug(f"Rule validated successfully: {rule}")
                return rule
            else:
                self.logger.error(
                    f"Validation failed for rule: {rule}\nStdout: {result.stdout}\nStderr: {result.stderr}"
                )
                return None
        except Exception as e:
            self.logger.error(f"Validation error for rule {rule}: {e}")
            return None
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    async def _write_rules(self, rules: List[str]):
        async with self.write_lock:
            backup = f"{self.rule_file}.bak"
            existing_rules: List[str] = []
            if os.path.exists(self.rule_file):
                try:
                    with open(self.rule_file, "r") as f:
                        existing_rules = [line.strip() for line in f if line.strip()]
                    self.logger.debug(
                        f"Read {len(existing_rules)} existing rules from {self.rule_file}"
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to read existing rules from {self.rule_file}: {e}"
                    )
                    existing_rules = []
            else:
                self.logger.debug(
                    f"Rule file {self.rule_file} does not exist, creating new"
                )

            sid_to_rule = {}
            for rule in existing_rules + rules:
                match = re.search(r"sid:(\d+);", rule)
                if match:
                    sid_to_rule[match.group(1)] = rule
                else:
                    self.logger.warning(f"Skipping rule without SID: {rule}")

            combined_rules = list(sid_to_rule.values())
            self.logger.debug(f"Combined {len(combined_rules)} unique rules")

            try:
                if os.path.exists(self.rule_file):
                    os.replace(self.rule_file, backup)
                    self.logger.debug(f"Created backup at {backup}")
                else:
                    self.logger.debug("No existing rule file to back up")
            except Exception as e:
                self.logger.error(f"Failed to create backup: {e}")

            try:
                with open(self.rule_file, "w") as f:
                    f.write("\n".join(combined_rules) + "\n")
                self.logger.info(
                    f"Successfully wrote {len(combined_rules)} rules to {self.rule_file}"
                )
            except Exception as e:
                self.logger.error(f"Failed to write rules to {self.rule_file}: {e}")
                if os.path.exists(backup):
                    os.replace(backup, self.rule_file)
                    self.logger.info(f"Restored backup from {backup}")
                raise

    async def reload_suricata(self):
        try:
            for _ in range(10):
                if os.path.exists(self.pid_file):
                    break
                await asyncio.sleep(0.5)
            subprocess.run(["suricatasc", "-c", "reload-rules"], check=True, timeout=10)
        except Exception as e:
            self.logger.error(f"Reload failed: {e}")
            raise

    async def _get_pid_from_file(self) -> Optional[int]:
        try:
            if os.path.exists(self.pid_file):
                with open(self.pid_file) as f:
                    return int(f.read().strip())
        except Exception as e:
            self.logger.warning(f"PID file error: {e}")
        return None

    async def _is_process_alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    async def _restart_suricata_service(self):
        for attempt in range(3):
            try:
                subprocess.run(
                    ["systemctl", "restart", "suricata"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.logger.info("Suricata service restarted successfully")
                return
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Service restart failed: {e.stderr}")
                await asyncio.sleep(2**attempt)
        raise RuntimeError("Failed to restart Suricata service after 3 attempts")
