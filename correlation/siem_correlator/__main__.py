"""Vong lap chinh cua correlator.

Chay:
    python -m siem_correlator             # chay lien tuc theo POLL_INTERVAL
    python -m siem_correlator --once      # chay 1 vong roi thoat (dung khi demo)
    python -m siem_correlator --dry-run   # chi in finding, khong ghi alert
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time

from .config import Settings
from .engine import CorrelationEngine
from .indexer import IndexerClient
from .rules import load_rules
from .sinks import IndexerSink, ManagerSink

log = logging.getLogger("siem_correlator")

_running = True


def _stop(signum, frame):  # noqa: ARG001
    global _running
    log.info("Nhan tin hieu %s, dung correlator", signum)
    _running = False


def run_cycle(engine: CorrelationEngine, rules, sinks, dry_run: bool) -> int:
    emitted = 0
    for rule in rules:
        for finding in engine.run(rule):
            if dry_run:
                print(json.dumps(finding.to_document(), ensure_ascii=False, indent=2))
            else:
                for sink in sinks:
                    sink.emit(finding)
            emitted += 1
    return emitted


def main() -> int:
    parser = argparse.ArgumentParser(prog="siem_correlator")
    parser.add_argument("--once", action="store_true", help="chay mot vong roi thoat")
    parser.add_argument("--dry-run", action="store_true", help="in finding thay vi ghi alert")
    args = parser.parse_args()

    settings = Settings.from_env()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    rules = load_rules(settings.rules_path)
    if not rules:
        log.error("Khong co rule nao de chay")
        return 1

    client = IndexerClient(
        settings.indexer_url, settings.username, settings.password, settings.verify_certs
    )

    # Cho Indexer san sang (container khoi dong cham hon correlator)
    for attempt in range(30):
        if client.ping():
            break
        log.info("Cho Wazuh Indexer... (%d/30)", attempt + 1)
        time.sleep(10)
    else:
        log.error("Indexer khong phan hoi, thoat")
        return 1

    engine = CorrelationEngine(client, settings.alerts_index)

    sinks = []
    if not args.dry_run:
        sinks.append(IndexerSink(client, settings.output_index_prefix))
        if settings.manager_socket:
            sinks.append(ManagerSink(settings.manager_socket))

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while _running:
        started = time.time()
        count = run_cycle(engine, rules, sinks, args.dry_run)
        log.info("Vong quet xong: %d alert tuong quan, %.1fs", count, time.time() - started)
        if args.once:
            break
        slept = 0
        while _running and slept < settings.poll_interval:
            time.sleep(1)
            slept += 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
