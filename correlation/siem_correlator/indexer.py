"""Client mong cho Wazuh Indexer (OpenSearch) - chi dung REST + requests."""

from __future__ import annotations

import json
import logging
from typing import Any

import requests
import urllib3

log = logging.getLogger(__name__)


class IndexerClient:
    def __init__(self, url: str, username: str, password: str, verify: bool = False, timeout: int = 30):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify
        self.session.headers.update({"Content-Type": "application/json"})
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def ping(self) -> bool:
        try:
            r = self.session.get(f"{self.url}/", timeout=self.timeout)
            return r.status_code == 200
        except requests.RequestException as exc:
            log.warning("Khong ket noi duoc Indexer: %s", exc)
            return False

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self.session.post(
            f"{self.url}/{index}/_search",
            data=json.dumps(body),
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def index_doc(self, index: str, doc_id: str, doc: dict[str, Any]) -> None:
        """Ghi 1 document voi _id tu tinh -> chay lai khong sinh ban trung."""
        r = self.session.put(
            f"{self.url}/{index}/_doc/{doc_id}",
            data=json.dumps(doc),
            timeout=self.timeout,
        )
        if r.status_code >= 400:
            log.error("Ghi alert that bai (%s): %s", r.status_code, r.text[:500])
        r.raise_for_status()

    def ensure_index_template(self, name: str, template: dict[str, Any]) -> None:
        r = self.session.put(
            f"{self.url}/_index_template/{name}",
            data=json.dumps(template),
            timeout=self.timeout,
        )
        if r.status_code >= 400:
            log.error("Tao index template that bai (%s): %s", r.status_code, r.text[:500])
        else:
            log.info("Index template '%s' san sang", name)
