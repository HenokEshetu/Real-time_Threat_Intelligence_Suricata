# src/redis_handler.py
import redis
import logging
import json
import asyncio
from typing import AsyncGenerator, Optional
from .config import settings, stix_mapping, channel_to_stix

class RedisManager:
    def __init__(self):
        self._client: Optional[redis.Redis] = None
        self._pubsub: Optional[redis.client.PubSub] = None
        self.logger = logging.getLogger("redis")
        self.rate_limiter = asyncio.Semaphore(10)
        self._connect()
        
        self.channel_map = channel_to_stix  # Use pre-defined mapping
        self.channels = list(self.channel_map.keys())
    def _connect(self):
        """Establish Redis connection"""
        self._client = redis.Redis.from_url(
            str(settings.redis_uri),
            socket_timeout=10,
            socket_keepalive=True,
            retry_on_timeout=True,
            max_connections=100,
            decode_responses=True
        )
        self._pubsub = self._client.pubsub()

    async def _get_message(self):
        """Retrieve message from Redis with async handling"""
        try:
            message = self._pubsub.get_message(
                ignore_subscribe_messages=True,
                timeout=1  # Shorter timeout for better async handling
            )
            if message:
                return self._process_message(message)
        except redis.RedisError as e:
            self.logger.error(f"Redis error: {str(e)}")
            raise ConnectionError("Redis connection lost")
        return None

    def _process_message(self, message) -> Optional[dict]:
        """Parse and validate Redis message"""
        try:
            data = json.loads(message['data'])
            channel = message['channel']
            data['stix_type'] = self.channel_map[channel]
            return data
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON: {message.get('data', 'unknown')}")
        except KeyError as e:
            self.logger.error(f"Missing message field: {str(e)}")
        except Exception as e:
            self.logger.error(f"Message processing error: {str(e)}")
        return None

    async def _reconnect(self):
        """Re-establish Redis connection with backoff"""
        self.logger.error("Redis connection lost, reconnecting...")
        for attempt in range(5):
            try:
                self._connect()
                self._pubsub.subscribe(*self.channels)
                if self._client.ping():
                    self.logger.info("Redis reconnected successfully")
                    return
            except redis.RedisError:
                wait = min(2 ** attempt, 10)
                self.logger.debug(f"Retry {attempt + 1}/5 after {wait}s")
                await asyncio.sleep(wait)
        raise ConnectionError("Failed to reconnect to Redis after 5 attempts")

    async def _recover_missed(self):
        """Attempt to recover missed messages after reconnection"""
        try:
            # Check for recent messages in a backup stream (if using Redis Streams)
            # This is a placeholder for actual recovery logic
            return []
        except Exception as e:
            self.logger.error(f"Message recovery failed: {str(e)}")
            return []

    async def message_generator(self) -> AsyncGenerator[dict, None]:
        """Asynchronous message generator with buffering and reconnection"""
        buffer = []
        self._pubsub.subscribe(*self.channels)
        self.logger.info(f"Subscribed to channels: {self.channels}")

        while True:
            try:
                # Process buffer first
                while buffer:
                    yield buffer.pop(0)
                
                # Get new messages
                message = await self._get_message()
                if message:
                    buffer.append(message)
                
                await asyncio.sleep(0.01)  # Yield control to event loop

            except ConnectionError:
                buffer += await self._recover_missed()
                await self._reconnect()
                continue
            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}")
                await asyncio.sleep(1)

    def keys(self, pattern: str) -> list:
        """Retrieve keys matching the given pattern from Redis"""
        return self._client.keys(pattern)