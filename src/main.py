# src/main.py
import asyncio
import logging
import signal
import json
import redis
from prometheus_client import Counter, Gauge, start_http_server
from .config import settings, stix_mapping
from .redis_handler import RedisManager
from .suricata_manager import SuricataManager
from .stix_processor import STIXProcessor


class IntegrationService:
    def __init__(self):
        self.running = False
        self.redis = RedisManager()
        self.redis_client = redis.Redis.from_url(str(settings.redis_uri))
        self.suricata = SuricataManager(self.redis_client)
        self.processor = STIXProcessor()
        self.logger = logging.getLogger("main")

        # Metrics
        self.messages_processed = Counter(
            "cti_messages_processed_total",
            "Total STIX messages processed",
            ["stix_type"],
        )
        self.errors_total = Counter(
            "cti_errors_total", "Total errors encountered", ["error_type"]
        )
        self.redis_connections = Gauge(
            "cti_redis_connections_active", "Active Redis connections"
        )
        self.rules_active = Gauge("cti_suricata_rules_active", "Active Suricata rules")
        self.reloads_total = Counter(
            "cti_suricata_reloads_total", "Total Suricata reloads"
        )
        self.cache_hits = Counter("cti_rule_cache_hits_total", "Total rule cache hits")

    async def handle_signal(self):
        self.running = False
        self.logger.info("Shutting down gracefully...")
        await self.suricata.update_rules([])
        self.redis_client.close()

    async def write_to_log(self, data: dict):
        try:
            with open(settings.threat_log_file, "a") as f:
                f.write(json.dumps(data) + "\n")
            self.logger.info(f"Wrote STIX object: {data['type']}")
        except Exception as e:
            self.logger.error(f"Log write error: {e}")
            self.errors_total.labels(error_type="log_write").inc()

    async def process_message(self, message: dict):
        try:
            stix_type = message["stix_type"]
            # Normalize types to compare
            original_type = message.get("type", "").lower().replace("-", "")
            expected_type = stix_type.lower().replace("-", "")
            if expected_type not in original_type:
                self.logger.debug(
                    f"Type mismatch: {message.get('type', '')} vs {stix_type}"
                )
                return

            obj_id = message.get("id")
            if obj_id and self.redis_client.exists(f"processed:{obj_id}"):
                self.logger.debug(f"Skipping duplicate object: {obj_id}")
                return

            self.messages_processed.labels(stix_type=stix_type).inc()
            await self.write_to_log(message)

            if obj_id:
                self.redis_client.setex(f"processed:{obj_id}", settings.rule_ttl, 1)

            mapping = stix_mapping.get(stix_type)
            if not mapping:
                self.logger.debug(f"No mapping for STIX type: {stix_type}")
                return

            field, action = mapping
            value = message.get(field)
            rules = []

            if action == "parse":
                if stix_type == "indicator":
                    if not value or not isinstance(value, str):
                        self.logger.warning(f"Invalid indicator pattern: {value}")
                        return
                    observables = self.processor.parse_indicator(value)
                    self.logger.debug(
                        f"Extracted observables from indicator: {observables}"
                    )

                elif stix_type == "observed-data":
                    observables = self.processor.parse_observed_data(value)
                    self.logger.debug(
                        f"Extracted observables from observed-data: {observables}"
                    )
                else:
                    observables = []

                for obs in observables:
                    rule = self.suricata.generate_rule(obs["type"], obs["value"])
                    if rule:
                        self.logger.debug(
                            f"Generated rule for {obs['type']}: {rule[0]}"
                        )
                        rules.append(rule)
                    else:
                        self.logger.debug(
                            f"Rule skipped due to cache hit: {obs['type']}={obs['value']}"
                        )
                        self.cache_hits.inc()

            else:
                if stix_type == "file":
                    hashes = message.get("hashes", {})
                    for hash_type in ["SHA-256", "SHA-1", "MD5"]:
                        hash_value = hashes.get(hash_type)
                        if hash_value:
                            if self.processor.validate_observable("hash", hash_value):
                                rule = self.suricata.generate_rule("hash", hash_value)
                                if rule:
                                    self.logger.debug(
                                        f"Generated rule for {hash_type}: {rule[0]}"
                                    )
                                    rules.append(rule)
                                else:
                                    self.logger.debug(
                                        f"Rule skipped due to cache hit: {hash_type}={hash_value}"
                                    )
                                    self.cache_hits.inc()
                            else:
                                self.logger.warning(
                                    f"Invalid {hash_type} value: {hash_value}"
                                )
                            break
                elif value and self.processor.validate_observable(action, value):
                    rule = self.suricata.generate_rule(action, value)
                    if rule:
                        self.logger.debug(f"Generated rule for {action}: {rule[0]}")
                        rules.append(rule)
                    else:
                        self.logger.debug(
                            f"Rule skipped due to cache hit: {action}={value}"
                        )
                        self.cache_hits.inc()

            if rules:
                self.logger.info(f"Processing {len(rules)} rules for storage")
                await self.suricata.update_rules(rules)
                key_count = len(
                    self.redis_client.keys(f"{self.suricata.rule_cache_key}:*")
                )
                self.rules_active.set(key_count)
                self.reloads_total.inc()
            else:
                self.logger.info("No rules generated for this message")

        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON: {message.get('data', 'unknown')}")
            self.errors_total.labels(error_type="json_decode").inc()
        except Exception as e:
            self.logger.error(f"Processing error: {e}")
            self.errors_total.labels(error_type="processing").inc()

    async def run(self):
        self.running = True
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig, lambda: asyncio.create_task(self.handle_signal())
            )

        start_http_server(8000)
        self.redis_connections.set(1)
        self.logger.info("Starting CTI-Suricata integration")

        async for message in self.redis.message_generator():
            if not self.running:
                break
            await self.process_message(message)

        self.redis_connections.set(0)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='{"time": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}',
        handlers=[
            logging.FileHandler("/var/log/cti-suricata/suricata-cti-integration.log"),
            logging.StreamHandler(),
        ],
    )
    service = IntegrationService()
    asyncio.run(service.run())
