"""Doc cau hinh tu bien moi truong."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    indexer_url: str
    username: str
    password: str
    verify_certs: bool
    alerts_index: str
    output_index_prefix: str
    rules_path: str
    poll_interval: int
    lookback_slack: int
    log_level: str
    manager_socket: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            indexer_url=os.getenv("INDEXER_URL", "https://wazuh.indexer:9200").rstrip("/"),
            username=os.getenv("INDEXER_USERNAME", "admin"),
            password=os.getenv("INDEXER_PASSWORD", "SecretPassword"),
            verify_certs=_env_bool("INDEXER_VERIFY_CERTS", False),
            alerts_index=os.getenv("ALERTS_INDEX", "wazuh-alerts-*"),
            output_index_prefix=os.getenv("OUTPUT_INDEX_PREFIX", "siem-correlated"),
            rules_path=os.getenv("RULES_PATH", "rules"),
            poll_interval=int(os.getenv("POLL_INTERVAL", "60")),
            lookback_slack=int(os.getenv("LOOKBACK_SLACK", "60")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            manager_socket=os.getenv("MANAGER_SOCKET") or None,
        )
