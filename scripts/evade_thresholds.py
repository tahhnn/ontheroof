#!/usr/bin/env python3
"""Tinh huong B: ke tan cong DA BIET nguong cua he thong va co tinh chay duoi nguong.

Kich ban: repo cua do an la public, ke tan cong doc duoc toan bo nguong trong
custom/rules/local_rules.xml va correlation/rules/smb_attack_chain.yml, roi dieu
chinh toc do tan cong cho vua du duoi nguong.

    python scripts/evade_thresholds.py --mode evade    # chay duoi nguong
    python scripts/evade_thresholds.py --mode loud     # cung tan cong, chay tren nguong

Chay ca hai roi so alert sinh ra: do chinh la bang chung dinh luong cho phan
"tinh ben vung cua phat hien dua-tren-nguong" trong bao cao.

CANH BAO ve thoi gian: che do --evade CHAM CO Y - no phai keo dai hon cua so cua
rule thi moi ne duoc. Mac dinh khoang 11 phut. Dung --compress de rut ngan khi
demo, nhung luc do ket qua khong con dung nua (xem canh bao script in ra).

Nguong bi ne (doc tu ma nguon, khong phai doan):
  100120 brute force       frequency=6  timeframe=120  same_source_ip + same_user
  100121 spraying          frequency=8  timeframe=300  same_source_ip + different dstuser
  100131 xuat hang loat    rows >= 10000 (pcre2 ^[1-9][0-9]{4,}$)
  mass_data_export_by_user min_count=5  window=1800
  brute_force_then_success stage 1 doi rule.id 100120/100121/5710/5712/60122
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from datetime import datetime

ERP_HOST = "erp01"
ERP_TAG = "erpapp"
TARGET_USER = "ketoan1"

# Ke tan cong luan phien qua nhieu IP de pha <same_source_ip /> cua rule 100120.
BOTNET_IPS = [
    "203.0.113.10", "203.0.113.11", "198.51.100.20",
    "198.51.100.21", "192.0.2.30", "192.0.2.31",
]


def syslog_line(host: str, tag: str, message: str) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"<13>{ts} {host} {tag}: {message}"


def ev_auth_fail(user: str, srcip: str) -> str:
    return f"AUTH result=FAILED user={user} srcip={srcip} reason=bad_password path=/api/login"


def ev_auth_ok(user: str, srcip: str) -> str:
    return f"AUTH result=OK user={user} srcip={srcip} reason=none path=/api/login"


def ev_export(user: str, srcip: str, rows: int) -> str:
    return f"EXPORT rows={rows} module=customer user={user} srcip={srcip} file=customer.csv"


class Sender:
    def __init__(self, host: str, port: int, print_only: bool):
        self.host, self.port = host, port
        self.sock = None if print_only else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.count = 0

    def send(self, message: str) -> None:
        line = syslog_line(ERP_HOST, ERP_TAG, message)
        self.count += 1
        print(f"[{self.count:3d}] {line}")
        if self.sock:
            self.sock.sendto(line.encode(), (self.host, self.port))

    def close(self) -> None:
        if self.sock:
            self.sock.close()


# ---------- che do ne nguong ----------


def run_evade(tx: Sender, scale: float) -> None:
    """Do mat khau duoi nguong 100120, roi xuat du lieu duoi nguong 100131.

    Ba thu thuat ne, moi thu nham vao mot dieu kien cu the cua rule:

    1. Doi IP sau moi 2 lan thu  -> pha <same_source_ip /> cua 100120.
       100120 can 6 lan that bai CUNG mot IP trong 120s; moi IP chi thay 2 lan.

    2. Chi nham DUY NHAT mot tai khoan -> pha <different_field>dstuser</different_field>
       cua 100121. Spraying doi 8 tai khoan KHAC NHAU tu cung mot IP.

    3. Xuat 9999 dong x 4 lan -> duoi ca hai nguong cung luc:
       - 9999 < 10000 nen khong khop pcre2 ^[1-9][0-9]{4,}$ cua 100131
       - 4 < 5 nen khong dat min_count cua mass_data_export_by_user
       Tong du lieu lay ra van la 39996 dong.
    """
    print("\n=== BUOC 1: do mat khau duoi nguong ===")
    print("5 lan thu / 130 giay, doi IP sau moi 2 lan\n")
    for i in range(5):
        ip = BOTNET_IPS[i // 2]
        tx.send(ev_auth_fail(TARGET_USER, ip))
        if i < 4:
            time.sleep(26 * scale)  # 5 lan trai deu tren 130s > timeframe 120s cua 100120

    print("\n=== BUOC 2: dang nhap thanh cong ===")
    print("Khong co 100120/100121 truoc do -> stage 1 cua brute_force_then_success rong\n")
    tx.send(ev_auth_ok(TARGET_USER, BOTNET_IPS[-1]))
    time.sleep(2 * scale)

    print("\n=== BUOC 3: xuat du lieu duoi ca hai nguong ===")
    print("4 lan x 9999 dong = 39996 dong, van duoi nguong\n")
    for i in range(4):
        tx.send(ev_export(TARGET_USER, BOTNET_IPS[-1], 9999))
        if i < 3:
            time.sleep(20 * scale)


# ---------- che do doi chung ----------


def run_loud(tx: Sender, scale: float) -> None:
    """Cung mot muc tieu, nhung chay tren nguong - dung lam nhom doi chung.

    Moi thay doi so voi che do evade la TOC DO va MOT IP DUY NHAT, khong doi
    ban chat hanh vi. Ke tan cong lay ra luong du lieu tuong duong.
    """
    ip = BOTNET_IPS[0]
    print("\n=== BUOC 1: do mat khau tren nguong ===")
    print("8 lan / 8 giay, cung mot IP, cung mot tai khoan -> dat 100120\n")
    for _ in range(8):
        tx.send(ev_auth_fail(TARGET_USER, ip))
        time.sleep(1 * scale)

    print("\n=== BUOC 2: dang nhap thanh cong ===\n")
    tx.send(ev_auth_ok(TARGET_USER, ip))
    time.sleep(1 * scale)

    print("\n=== BUOC 3: xuat du lieu tren nguong ===")
    print("6 lan x ~40000 dong -> dat 100131 va mass_data_export_by_user\n")
    for _ in range(6):
        tx.send(ev_export(TARGET_USER, ip, random.randint(12000, 40000)))
        time.sleep(1 * scale)


EXPECTED = {
    "evade": [
        "100111 (that bai le, level 5) - VAN NO, nhung chim trong nhieu nen",
        "100110 (dang nhap thanh cong, level 3) - VAN NO",
        "100120 brute force               - KHONG no (doi IP moi 2 lan)",
        "100121 spraying                  - KHONG no (chi 1 tai khoan)",
        "100131 xuat hang loat            - KHONG no (9999 < 10000)",
        "mass_data_export_by_user         - KHONG no (4 < 5 lan)",
        "brute_force_then_success         - KHONG no (stage 1 rong)",
        "account_takeover_to_exfil        - KHONG no (stage 1 doi 100111 x3 trong 1h;",
        "                                   5 lan trai tren 130s VAN co the dat -> kiem tra thuc te)",
    ],
    "loud": [
        "100111 x8, 100120, 100110, 100130, 100131",
        "brute_force_then_success (critical)",
        "mass_data_export_by_user (high)",
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Tinh huong B: ne nguong phat hien")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--mode", choices=["evade", "loud"], default="evade")
    parser.add_argument(
        "--compress",
        type=float,
        default=1.0,
        help="he so rut ngan thoi gian cho (0.1 = nhanh gap 10). CHI dung de xem thu.",
    )
    parser.add_argument("--print-only", action="store_true")
    args = parser.parse_args()

    if args.mode == "evade" and args.compress < 1.0:
        print("!" * 70)
        print("CANH BAO: --compress < 1.0 lam mat hieu luc cua che do evade.")
        print("Ne nguong dua vao viec chay CHAM hon cua so cua rule. Rut ngan thoi gian")
        print("thi su kien don lai trong cua so va rule SE no - ket qua khong con y nghia.")
        print("Chi dung --compress de xem truoc luong su kien, khong dung de ket luan.")
        print("!" * 70 + "\n")

    started = datetime.now()
    print(f"Che do: {args.mode}   Bat dau: {started:%H:%M:%S}")
    if args.mode == "evade":
        print("Uoc tinh thoi gian: ~11 phut (co y cham de ne cua so cua rule)")
    print("\nAlert cho doi:")
    for line in EXPECTED[args.mode]:
        print(f"  - {line}")

    tx = Sender(args.host, args.port, args.print_only)
    try:
        if args.mode == "evade":
            run_evade(tx, args.compress)
        else:
            run_loud(tx, args.compress)
    except KeyboardInterrupt:
        print("\nDung theo yeu cau nguoi dung.")
    finally:
        tx.close()

    ended = datetime.now()
    print(f"\nDa gui {tx.count} su kien. Ket thuc: {ended:%H:%M:%S}")
    print("\nSo sanh ket qua hai che do:")
    print(
        f"  python scripts/eval_detection.py --count-window "
        f"'{started:%Y-%m-%dT%H:%M:%S}' '{ended:%Y-%m-%dT%H:%M:%S}'"
    )
    print("\nDoi voi hoi dong: chay ca hai che do, dua bang so alert canh nhau.")
    print("Chenh lech do chinh la muc do ben vung cua phat hien dua-tren-nguong.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
