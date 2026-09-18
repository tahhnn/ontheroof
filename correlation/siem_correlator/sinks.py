"""Noi nhan alert tuong quan sau khi engine sinh ra.

Hai duong ra:
  IndexerSink  - ghi thang vao index rieng (siem-correlated-*) de dung cho dashboard.
  ManagerSink  - ban JSON vao socket cua Wazuh manager de alert di qua ruleset
                 (rule 100900-100903) va huong duoc active response / email.
                 Chi hoat dong khi mount socket cua manager vao container.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone

from .engine import Finding
from .indexer import IndexerClient

log = logging.getLogger(__name__)

INDEX_TEMPLATE = {
    "index_patterns": ["siem-correlated-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "correlation_rule": {"type": "keyword"},
                "rule_name": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "summary": {"type": "text"},
                "description": {"type": "text"},
                "entity": {"type": "keyword"},
                "entity_field": {"type": "keyword"},
                "event_count": {"type": "long"},
                "window_seconds": {"type": "long"},
                "window_start": {"type": "date"},
                "window_end": {"type": "date"},
                "mitre_ids": {"type": "keyword"},
                "source": {"type": "keyword"},
                "evidence": {"type": "object", "enabled": False},
            }
        },
    },
}


class IndexerSink:
    def __init__(self, client: IndexerClient, index_prefix: str):
        self.client = client
        self.index_prefix = index_prefix
        self.client.ensure_index_template("siem-correlated", INDEX_TEMPLATE)

    def _index_name(self) -> str:
        return f"{self.index_prefix}-{datetime.now(timezone.utc):%Y.%m.%d}"

    def emit(self, finding: Finding) -> None:
        self.client.index_doc(self._index_name(), finding.doc_id, finding.to_document())


class ManagerSink:
    """Ghi vao unix datagram socket cua Wazuh manager.

    Dinh dang message: <queue>:<location>:<payload>
    queue 1 = so lieu tu chuong trinh ngoai, location bat dau bang dau ':' de
    Wazuh khong ghi de truong location.
    """

    QUEUE_ID = "1"
    LOCATION = "siem-correlator"

    def __init__(self, socket_path: str):
        self.socket_path = socket_path

    def emit(self, finding: Finding) -> None:
        payload = json.dumps(finding.to_document(), ensure_ascii=False)
        message = f"{self.QUEUE_ID}:{self.LOCATION}:{payload}".encode()
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(self.socket_path)
            sock.send(message)
            sock.close()
        except OSError as exc:
            log.error("Khong gui duoc alert vao manager socket %s: %s", self.socket_path, exc)
