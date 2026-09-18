#!/usr/bin/env python3
"""Cau hoi 13: do bo chi so danh gia phat hien - Recall, Precision, F1, FP/ngay.

Chin kich ban tan cong hien tai deu la true positive, nen chi tinh duoc Recall.
Thieu ve false positive thi khong co Precision, khong co F1. Script nay lam day
ve con thieu do.

Quy trinh do dung, ba buoc:

    # Buoc 1 - do FALSE POSITIVE tren luu luong lanh tinh
    python scripts/benign_traffic.py --profile both --duration 3600
    python scripts/eval_detection.py --fp-window '<bat dau>' '<ket thuc>'

    # Buoc 2 - do TRUE POSITIVE tren kich ban tan cong
    python scripts/eval_detection.py --recall

    # Buoc 3 - tong hop
    python scripts/eval_detection.py --report --tp 8 --fn 1 --fp 3 \\
        --hours 1 --endpoints 1

QUAN TRONG: buoc 1 va buoc 2 KHONG duoc chay chong len nhau ve thoi gian. Neu
tron lan thi khong con phan biet duoc alert nao la FP.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

try:
    import requests
    import urllib3
except ImportError:
    print("Thieu thu vien: pip install requests")
    sys.exit(1)

INDEXER_URL = os.getenv("INDEXER_URL", "https://localhost:9200").rstrip("/")
USERNAME = os.getenv("INDEXER_USERNAME", "admin")
PASSWORD = os.getenv("INDEXER_PASSWORD", "SecretPassword")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Kich ban -> rule tuong quan phai no. Lay tu bang EXPECTED trong simulate_attack.py.
# Chi liet ke kich ban co ky vong ve rule TUONG QUAN; kich ban chi sinh alert
# Wazuh don le (bruteforce, spray, portscan) khong tinh vao Recall cua engine.
SCENARIO_EXPECT = {
    "exfil": ["mass_data_export_by_user"],
    "scan-then-login": ["scan_then_login_attempt"],
    "impossible-travel": ["impossible_travel"],
    "insider": ["mass_data_export_by_user"],
    "full": ["brute_force_then_success", "account_takeover_to_exfil"],
}


def session() -> requests.Session:
    s = requests.Session()
    s.auth = (USERNAME, PASSWORD)
    s.verify = False
    s.headers.update({"Content-Type": "application/json"})
    return s


def search(s: requests.Session, index: str, body: dict) -> dict:
    r = s.post(
        f"{INDEXER_URL}/{index}/_search",
        data=json.dumps(body),
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def parse_ts(raw: str) -> str:
    """Chap nhan '2026-09-09T14:30:00' hoac 'now-1h'."""
    if raw.startswith("now"):
        return raw
    return datetime.fromisoformat(raw).astimezone(timezone.utc).isoformat()


# ---------- do false positive ----------


def count_fp(s: requests.Session, start: str, end: str) -> int:
    """Dem alert tuong quan trong khoang thoi gian chi co luu luong lanh tinh.

    MOI alert trong khoang nay deu la duong tinh gia theo dinh nghia.
    """
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": start, "lt": end}}}]}},
        "aggs": {
            "theo_rule": {
                "terms": {"field": "correlation_rule", "size": 20},
                "aggs": {"doi_tuong": {"terms": {"field": "entity", "size": 5}}},
            },
            "theo_muc": {"terms": {"field": "severity", "size": 5}},
        },
    }
    res = search(s, "siem-correlated-*", body)
    total = res["hits"]["total"]["value"]
    aggs = res.get("aggregations", {})

    print(f"\nKhoang do: {start}  ->  {end}")
    print(f"Tong alert tuong quan: {total}")
    print("Moi alert trong khoang nay deu la DUONG TINH GIA (khong co tan cong).\n")

    buckets = aggs.get("theo_rule", {}).get("buckets", [])
    if not buckets:
        print("  Khong co alert tuong quan nao.")
        print("  -> Precision cua lop tuong quan tren luu luong nay la 100%.")
    else:
        print(f"  {'Rule':<32} {'So FP':>6}   Doi tuong bi bao nham")
        print("  " + "-" * 74)
        for b in buckets:
            ents = ", ".join(e["key"] for e in b["doi_tuong"]["buckets"][:3])
            print(f"  {b['key']:<32} {b['doc_count']:>6}   {ents}")

        print("\n  Theo muc do:")
        for b in aggs.get("theo_muc", {}).get("buckets", []):
            print(f"    {b['key']:<10} {b['doc_count']:>5}")

    # Alert Wazuh tho - de doi chieu, khong tinh vao Precision cua engine.
    raw = search(
        s,
        "wazuh-alerts-*",
        {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start, "lt": end}}},
                        {"range": {"rule.level": {"gte": 10}}},
                    ]
                }
            },
        },
    )
    print(f"\n  (Doi chieu: {raw['hits']['total']['value']} alert Wazuh muc >= 10 cung khoang.")
    print("   Con so nay KHONG tinh vao Precision cua engine tuong quan,")
    print("   nhung no la nhieu nen ma nguoi truc phai doc moi ngay.)")
    return total


# ---------- do recall ----------


def measure_recall(s: requests.Session, delay: float, scenarios: list[str]) -> None:
    """Chay tung kich ban, doi correlator quet, kiem tra rule ky vong co no khong."""
    results = []
    for name in scenarios:
        expect = SCENARIO_EXPECT[name]
        print("\n" + "=" * 74)
        print(f"KICH BAN: {name}   ky vong: {', '.join(expect)}")
        print("=" * 74)

        started = datetime.now(timezone.utc)
        cmd = [
            sys.executable, "scripts/simulate_attack.py",
            "--scenario", name, "--delay", str(delay),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"  Chay kich ban that bai: {proc.stderr[:300]}")
            results.append((name, expect, [], False))
            continue
        print(f"  Da gui su kien. Doi correlator quet ({POLL_INTERVAL + 15}s)...")
        time.sleep(POLL_INTERVAL + 15)

        res = search(
            s,
            "siem-correlated-*",
            {
                "size": 50,
                "query": {
                    "bool": {"filter": [{"range": {"@timestamp": {"gte": started.isoformat()}}}]}
                },
                "_source": ["correlation_rule", "severity", "summary"],
            },
        )
        fired = {h["_source"]["correlation_rule"] for h in res["hits"]["hits"]}
        hit = [r for r in expect if r in fired]
        miss = [r for r in expect if r not in fired]

        for r in hit:
            print(f"  [TP]  {r}")
        for r in miss:
            print(f"  [FN]  {r}  - KHONG no")
        extra = fired - set(expect)
        for r in sorted(extra):
            print(f"  [?]   {r}  - no ngoai ky vong (co the do du lieu con lai tu lan truoc)")

        results.append((name, expect, hit, not miss))

    print("\n" + "=" * 74)
    print("TONG HOP RECALL")
    print("=" * 74)
    tp = sum(len(h) for _, _, h, _ in results)
    total = sum(len(e) for _, e, _, _ in results)
    fn = total - tp
    print(f"\n  {'Kich ban':<20} {'Ky vong':>8} {'Bat duoc':>10}   Ket qua")
    print("  " + "-" * 60)
    for name, expect, hit, full in results:
        mark = "dat" if full else "THIEU"
        print(f"  {name:<20} {len(expect):>8} {len(hit):>10}   {mark}")
    print("  " + "-" * 60)
    print(f"  {'TONG':<20} {total:>8} {tp:>10}")
    if total:
        print(f"\n  Recall = TP/(TP+FN) = {tp}/{total} = {tp / total:.1%}")
    print(f"\n  Dung cho buoc 3:  --tp {tp} --fn {fn}")
    print("\n  LUU Y trung thuc: day la Recall tren chinh bo kich ban do minh viet")
    print("  (kiem chung vong tron - xem cau 12). No do do THONG SUOT cua chuoi xu ly,")
    print("  khong do duoc kha nang phat hien tan cong that.")


# ---------- tong hop ----------


def report(tp: int, fn: int, fp: int, hours: float, endpoints: int) -> None:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print("\n" + "=" * 62)
    print("BO CHI SO DANH GIA PHAT HIEN")
    print("=" * 62)
    print(f"\n  True positive  (TP): {tp}")
    print(f"  False negative (FN): {fn}")
    print(f"  False positive (FP): {fp}")
    print(f"\n  Recall    = TP/(TP+FN) = {recall:.1%}")
    print(f"  Precision = TP/(TP+FP) = {precision:.1%}")
    print(f"  F1                     = {f1:.1%}")

    if hours > 0 and endpoints > 0:
        per_day = fp / hours * 24
        per_day_per_ep = per_day / endpoints
        print(f"\n  FP/ngay              = {per_day:.1f}")
        print(f"  FP/ngay/endpoint     = {per_day_per_ep:.2f}")
        print("\n  " + "-" * 58)
        print("  FP/ngay la chi so QUAN TRONG NHAT voi de tai nay.")
        print("  Mot SME 50 may chiu duoc chung vai alert moi ngay.")
        if per_day > 20:
            print(f"\n  -> {per_day:.0f} alert/ngay la QUA NHIEU voi SME khong co SOC.")
            print("     Du Recall 100% thi he thong van vo dung vi khong ai doc het.")
            print("     Can: nang nguong, hoac them allowlist (cau 14).")
        elif per_day > 5:
            print(f"\n  -> {per_day:.0f} alert/ngay la o muc chap nhan duoc, nhung nen tinh chinh.")
        else:
            print(f"\n  -> {per_day:.1f} alert/ngay - muc nay mot nguoi kiem nhiem xu ly duoc.")

    print("\n  " + "-" * 58)
    print("  Khi dua vao bao cao, phai ghi kem dieu kien do:")
    print("    - FP do tren luu luong lanh tinh do chinh minh sinh ra,")
    print("      chua phai luu luong that cua doanh nghiep.")
    print("    - TP do tren bo kich ban do chinh minh viet (kiem chung vong tron).")
    print("  Khong ghi dieu kien do thi con so mat y nghia khoa hoc.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Do bo chi so danh gia phat hien")
    parser.add_argument("--fp-window", nargs=2, metavar=("BAT_DAU", "KET_THUC"),
                        help="dem FP trong khoang thoi gian (ISO hoac 'now-1h')")
    parser.add_argument("--count-window", nargs=2, metavar=("BAT_DAU", "KET_THUC"),
                        help="dem alert trong khoang (dung cho tinh huong B)")
    parser.add_argument("--recall", action="store_true", help="chay cac kich ban va do Recall")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="--delay truyen cho simulate_attack.py (giu <= 1.0)")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIO_EXPECT),
                        help="chi chay kich ban nay (lap lai duoc); mac dinh chay tat ca")
    parser.add_argument("--report", action="store_true", help="tong hop chi so")
    parser.add_argument("--tp", type=int, default=0)
    parser.add_argument("--fn", type=int, default=0)
    parser.add_argument("--fp", type=int, default=0)
    parser.add_argument("--hours", type=float, default=0)
    parser.add_argument("--endpoints", type=int, default=1)
    args = parser.parse_args()

    if args.report:
        report(args.tp, args.fn, args.fp, args.hours, args.endpoints)
        return 0

    s = session()
    try:
        s.get(f"{INDEXER_URL}/", timeout=10).raise_for_status()
    except requests.RequestException as exc:
        print(f"Khong ket noi duoc Indexer tai {INDEXER_URL}: {exc}")
        return 1

    if args.fp_window or args.count_window:
        window = args.fp_window or args.count_window
        n = count_fp(s, parse_ts(window[0]), parse_ts(window[1]))
        if args.fp_window:
            hours = 0.0
            if not window[0].startswith("now"):
                delta = datetime.fromisoformat(window[1]) - datetime.fromisoformat(window[0])
                hours = delta.total_seconds() / 3600
            print(f"\nDung cho buoc 3:  --fp {n}" + (f" --hours {hours:.2f}" if hours else ""))
        return 0

    if args.recall:
        measure_recall(s, args.delay, args.scenario or sorted(SCENARIO_EXPECT))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
