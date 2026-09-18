#!/usr/bin/env python3
"""Tinh huong C: noi gian im lang - lay du lieu deu dan trong 60 ngay.

Ke toan truong, tai khoan hop le, dang nhap dung gio hanh chinh tu dung may cua
minh, moi ngay xuat 1 bao cao khach hang. Khong rule nao cua he thong bat duoc.

VI SAO PHAI TIEM THANG VAO INDEXER, KHONG GUI QUA SYSLOG:
    Trong Wazuh, @timestamp cua alert la thoi diem MANAGER SINH RA alert, khong
    phai thoi diem ghi trong dong log. Gui syslog thi moi su kien deu mang dau
    thoi gian "bay gio", khong the tai hien hanh vi trai 60 ngay.
    Vi vay script nay ghi truc tiep document alert co @timestamp lui ve qua khu.

    Day la BO GA KIEM THU, khong phai duong di that cua du lieu. Alert duoc tiem
    mang truong "_synthetic": true de phan biet, va co the xoa sach bang --cleanup.

Cach dung:

    python scripts/slow_insider.py --inject          # tiem 60 ngay du lieu
    python scripts/slow_insider.py --analyze         # chung minh rule hien tai mu
    python scripts/slow_insider.py --cleanup         # xoa sach du lieu tiem vao

Muc dich truoc hoi dong: khong phai de "khoe" ma de CHUNG MINH DINH LUONG rang
kien truc hien tai mu voi nhom kich ban nay, va do chinh la ly do can loai rule
`cumulative` neu trong chuong huong phat trien.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
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

# Index nam trong pattern wazuh-alerts-* nen correlator DOC DUOC, nhung ten rieng
# de xoa sach ma khong dung toi du lieu that.
TEST_INDEX = "wazuh-alerts-4.x-synthetic-insider"

INSIDER = "ketoantruong"
INSIDER_IP = "192.168.10.24"
INSIDER_AGENT = "erp01"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def session() -> requests.Session:
    s = requests.Session()
    s.auth = (USERNAME, PASSWORD)
    s.verify = False
    s.headers.update({"Content-Type": "application/json"})
    return s


def make_alert(ts: datetime, rule_id: str, level: int, description: str, **data) -> dict:
    """Dung document alert theo dung so do cua wazuh-alerts-*."""
    return {
        "@timestamp": ts.isoformat(),
        "timestamp": ts.isoformat(),
        "rule": {
            "id": rule_id,
            "level": level,
            "description": description,
            "groups": ["erpapp", "synthetic"],
        },
        "agent": {"id": "001", "name": INSIDER_AGENT},
        "manager": {"name": "wazuh.manager"},
        "data": data,
        "_synthetic": True,
    }


def build_60_days() -> list[dict]:
    """Sinh 60 ngay hanh vi noi gian - deu dan, trong gio, duoi moi nguong.

    Moi ngay:
      08:0x  dang nhap thanh cong tu dung mot IP LAN     -> 100110 (level 3)
      1x:xx  xuat 1 bao cao khach hang, 300-900 dong     -> 100130 (level 5)

    Khong ngay nao dat nguong nao. Tong 60 ngay: khoang 36.000 dong du lieu
    khach hang di ra ngoai.
    """
    alerts = []
    now = datetime.now(timezone.utc)
    for day in range(60, 0, -1):
        base = (now - timedelta(days=day)).replace(minute=0, second=0, microsecond=0)

        # Cuoi tuan nghi - lam du lieu that hon, va cung lam ro rang hanh vi deu dan.
        if base.weekday() >= 5:
            continue

        login_at = base.replace(hour=1, minute=random.randint(0, 20))  # 08:0x gio VN = 01:0x UTC
        alerts.append(
            make_alert(
                login_at,
                "100110",
                3,
                f"erpapp: dang nhap thanh cong - user {INSIDER} tu {INSIDER_IP}",
                dstuser=INSIDER,
                srcip=INSIDER_IP,
                status="OK",
            )
        )

        rows = random.randint(300, 900)
        export_at = base.replace(hour=random.randint(2, 8), minute=random.randint(0, 59))
        alerts.append(
            make_alert(
                export_at,
                "100130",
                5,
                f"erpapp: xuat du lieu module nhay cam (customer) boi {INSIDER}",
                dstuser=INSIDER,
                srcip=INSIDER_IP,
                erp={"module": "customer", "rows": str(rows)},
            )
        )
    return alerts


def inject(s: requests.Session) -> int:
    alerts = build_60_days()
    lines = []
    for i, doc in enumerate(alerts):
        lines.append(json.dumps({"index": {"_index": TEST_INDEX, "_id": f"insider-{i}"}}))
        lines.append(json.dumps(doc))
    payload = "\n".join(lines) + "\n"

    r = s.post(
        f"{INDEXER_URL}/_bulk",
        data=payload.encode(),
        headers={"Content-Type": "application/x-ndjson"},
        params={"refresh": "true"},
        timeout=60,
    )
    if r.status_code >= 400:
        print(f"Tiem that bai ({r.status_code}): {r.text[:400]}")
        return 1

    body = r.json()
    if body.get("errors"):
        first = next(
            (item for item in body["items"] if item.get("index", {}).get("error")), None
        )
        print(f"Bulk co loi: {json.dumps(first, ensure_ascii=False)[:400]}")
        return 1

    total_rows = sum(
        int(a["data"]["erp"]["rows"]) for a in alerts if "erp" in a.get("data", {})
    )
    print(f"Da tiem {len(alerts)} alert vao index '{TEST_INDEX}'.")
    print(f"Trai deu tren 60 ngay, tong {total_rows} dong du lieu khach hang.")
    print("\nDoi mot chu ky quet cua correlator (60s) roi chay --analyze.")
    return 0


def analyze(s: requests.Session) -> int:
    """Chung minh dinh luong: rule hien tai mu, rule cumulative se bat duoc."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=61)

    print("=" * 72)
    print("PHAN 1 - Rule tuong quan hien tai co bat duoc khong?")
    print("=" * 72)

    r = s.post(
        f"{INDEXER_URL}/siem-correlated-*/_search",
        data=json.dumps(
            {
                "size": 20,
                "query": {"bool": {"filter": [{"term": {"entity": INSIDER}}]}},
            }
        ),
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        timeout=30,
    )
    hits = r.json().get("hits", {}).get("hits", []) if r.status_code < 400 else []
    if hits:
        print(f"\nCo {len(hits)} alert tuong quan cho '{INSIDER}':")
        for h in hits:
            src = h["_source"]
            print(f"  - {src['correlation_rule']}: {src['summary']}")
        print("\n(Neu co alert, kiem tra xem no den tu du lieu tiem vao hay tu nguon khac.)")
    else:
        print(f"\n  KHONG co alert tuong quan nao cho '{INSIDER}'.")
        print("  Dung nhu du doan trong docs/bao-ve-hoi-dong.md, tinh huong C.")
        print("\n  Ly do, tung rule mot:")
        print("    mass_data_export_by_user  - nguong 5 lan/30 phut; noi gian lam 1 lan/ngay")
        print("    100131 xuat hang loat     - can >= 10000 dong; moi lan chi 300-900")
        print("    100122 ngoai gio          - dang nhap trong gio hanh chinh")
        print("    impossible_travel         - 1 IP duy nhat")
        print("    account_takeover_to_exfil - khong co giai doan do mat khau")
        print("\n  Sau xa hon: cua so dai nhat trong toan he thong la 7200s (2 gio).")
        print("  Hanh vi trai 60 ngay nam ngoai tam nhin cua MOI rule, ve KIEN TRUC")
        print("  chu khong phai ve tinh chinh nguong.")

    print("\n" + "=" * 72)
    print("PHAN 2 - Neu co loai rule `cumulative` thi sao?")
    print("=" * 72)

    r = s.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        data=json.dumps(
            {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"terms": {"rule.id": ["100130", "100131"]}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start.isoformat(),
                                        "lt": end.isoformat(),
                                    }
                                }
                            },
                        ]
                    }
                },
                "aggs": {
                    "per_user": {"terms": {"field": "data.dstuser", "size": 20}}
                },
            }
        ),
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        timeout=30,
    )
    if r.status_code >= 400:
        print(f"Truy van that bai ({r.status_code}): {r.text[:300]}")
        return 1

    buckets = r.json().get("aggregations", {}).get("per_user", {}).get("buckets", [])
    if not buckets:
        print("\n  Khong co du lieu. Chay --inject truoc.")
        return 1

    print("\n  Tong so lan xuat du lieu trong 60 ngay, theo tai khoan:\n")
    print(f"  {'Tai khoan':<20} {'So lan xuat':>12}")
    print("  " + "-" * 34)
    for b in buckets:
        print(f"  {b['key']:<20} {b['doc_count']:>12}")

    print("\n  Voi mot rule dang:")
    print("      type: cumulative")
    print("      window: 5184000        # 60 ngay")
    print("      group_by: data.dstuser")
    print("      min_count: 30")
    print("\n  ...tai khoan noi gian se noi bat ngay - trong khi moi rule hien tai deu mu.")
    print("\n  Day la thay doi NHO voi engine: them mot loai rule dem tich luy va")
    print("  cho phep `window` lon. Khong doi kien truc.")
    return 0


def cleanup(s: requests.Session) -> int:
    r = s.delete(f"{INDEXER_URL}/{TEST_INDEX}", timeout=30)
    if r.status_code == 404:
        print(f"Index '{TEST_INDEX}' khong ton tai - khong co gi de xoa.")
        return 0
    if r.status_code >= 400:
        print(f"Xoa that bai ({r.status_code}): {r.text[:300]}")
        return 1
    print(f"Da xoa index '{TEST_INDEX}'.")
    print("Luu y: alert tuong quan da sinh ra trong siem-correlated-* KHONG bi xoa theo.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Tinh huong C: noi gian im lang 60 ngay")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--inject", action="store_true", help="tiem 60 ngay du lieu")
    group.add_argument("--analyze", action="store_true", help="chung minh rule hien tai mu")
    group.add_argument("--cleanup", action="store_true", help="xoa sach du lieu tiem vao")
    args = parser.parse_args()

    s = session()
    try:
        s.get(f"{INDEXER_URL}/", timeout=10).raise_for_status()
    except requests.RequestException as exc:
        print(f"Khong ket noi duoc Indexer tai {INDEXER_URL}: {exc}")
        print("Dat bien moi truong INDEXER_URL / INDEXER_PASSWORD neu khac mac dinh.")
        return 1

    if args.inject:
        return inject(s)
    if args.analyze:
        return analyze(s)
    return cleanup(s)


if __name__ == "__main__":
    sys.exit(main())
