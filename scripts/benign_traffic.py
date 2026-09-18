#!/usr/bin/env python3
"""Sinh luu luong LANH TINH gui vao Wazuh - dung de do false positive.

Dung cho hai muc dich khac nhau:

  1. Do FP rate (cau hoi 13 cua hoi dong). Chay che do --profile office trong
     nhieu gio. MOI alert sinh ra trong khoang thoi gian nay deu la DUONG TINH
     GIA, vi khong co hanh vi tan cong nao ca.

         python scripts/benign_traffic.py --profile office --duration 3600

  2. Tai hien "bao alert" (tinh huong A). Che do --storm mo phong su co ung dung:
     200 nhan vien cung dang nhap, moi nguoi that bai 1 lan roi thanh cong.

         python scripts/benign_traffic.py --storm --employees 200

Sau khi chay, dem alert bang scripts/eval_detection.py hoac truy van truc tiep
Indexer - xem cuoi file nay.

LUU Y: script nay KHONG duoc chay cung luc voi simulate_attack.py. Neu tron lan,
khong con phan biet duoc alert nao la FP.
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

# Nhan vien that: ten tieng Viet, dai IP LAN noi bo.
STAFF = [
    "nvhung", "ketoan1", "ketoan2", "thukho1", "thukho2",
    "banhang1", "banhang2", "banhang3", "ttmai", "lvminh",
    "phlong", "dtquyen", "nvtuan", "hrhoa", "itdung",
]

# Cac module nghiep vu duoc truy xuat hang ngay - deu la hop le.
MODULES = ["customer", "order", "invoice", "product", "report"]

# Tai khoan dich vu: job tu dong chay dem. Day chinh la nguon FP ma cau 14 noi toi.
SERVICE_ACCOUNTS = ["svc_etl", "svc_backup"]


def syslog_line(host: str, tag: str, message: str) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"<13>{ts} {host} {tag}: {message}"


def lan_ip() -> str:
    """IP trong dai LAN cua van phong."""
    return f"192.168.10.{random.randint(20, 200)}"


def remote_ip() -> str:
    """IP cong cong - nhan vien lam viec tu xa qua 4G/FTTH.

    Day la nguon FP chinh cua rule impossible_travel: cung mot nguoi doi qua lai
    giua Wi-Fi van phong, 4G va mang nha se cho ra nhieu IP khac nhau.
    """
    return random.choice(
        [
            f"14.161.{random.randint(1, 254)}.{random.randint(1, 254)}",   # FTTH VNPT
            f"113.161.{random.randint(1, 254)}.{random.randint(1, 254)}",  # FTTH Viettel
            f"171.224.{random.randint(1, 254)}.{random.randint(1, 254)}",  # 4G Viettel
        ]
    )


# ---------- su kien lanh tinh ----------


def ev_login_ok(user: str, srcip: str) -> str:
    return f"AUTH result=OK user={user} srcip={srcip} reason=none path=/api/login"


def ev_login_typo(user: str, srcip: str) -> str:
    """Go sai mat khau - chuyen binh thuong, KHONG phai tan cong.

    Sinh rule 100111 (level 5). Mot lan le khong du kich hoat 100120
    (can 6 lan/120s cung user cung IP).
    """
    return f"AUTH result=FAILED user={user} srcip={srcip} reason=bad_password path=/api/login"


def ev_report(user: str, srcip: str) -> str:
    """Xuat bao cao thuong ngay - so dong nho, duoi nguong 10000 cua rule 100131."""
    module = random.choice(MODULES)
    rows = random.randint(20, 800)
    return f"EXPORT rows={rows} module={module} user={user} srcip={srcip} file={module}.csv"


def ev_etl_export(user: str) -> str:
    """Job ETL chay dem - xuat nhieu dong, hop le hoan toan.

    Day la kich ban cau 14: job nay dat nguong 100131 (>= 10000 dong) VA neu chay
    du 5 lan trong 30 phut thi dat luon nguong mass_data_export_by_user.
    Ca hai deu la false positive.
    """
    rows = random.randint(15000, 90000)
    return f"EXPORT rows={rows} module=customer user={user} srcip=192.168.10.9 file=nightly.csv"


# ---------- ho so luu luong ----------


def profile_office(sock, host: str, port: int, duration: int, delay: float) -> int:
    """Mot ngay lam viec binh thuong: dang nhap, go sai, xuat bao cao nho.

    Ty le duoc chon theo quan sat thong thuong o van phong:
      - 5% lan dang nhap la go sai mat khau
      - moi nguoi lam viec tu xa khoang 20% thoi gian
    """
    sent = 0
    ended = time.time() + duration
    while time.time() < ended:
        user = random.choice(STAFF)
        srcip = remote_ip() if random.random() < 0.20 else lan_ip()

        if random.random() < 0.05:
            sent += _send(sock, host, port, ERP_HOST, ERP_TAG, ev_login_typo(user, srcip))
            time.sleep(delay)

        sent += _send(sock, host, port, ERP_HOST, ERP_TAG, ev_login_ok(user, srcip))
        time.sleep(delay)

        for _ in range(random.randint(0, 3)):
            sent += _send(sock, host, port, ERP_HOST, ERP_TAG, ev_report(user, srcip))
            time.sleep(delay)
    return sent


def profile_nightly(sock, host: str, port: int, runs: int, delay: float) -> int:
    """Job ETL chay dem - nguon false positive da biet (cau 14).

    Chay 20 lan nhu mot job that se lam no ca 100131 lan mass_data_export_by_user.
    """
    sent = 0
    for account in SERVICE_ACCOUNTS:
        sent += _send(sock, host, port, ERP_HOST, ERP_TAG, ev_login_ok(account, "192.168.10.9"))
        time.sleep(delay)
        for _ in range(runs):
            sent += _send(sock, host, port, ERP_HOST, ERP_TAG, ev_etl_export(account))
            time.sleep(delay)
    return sent


def profile_storm(sock, host: str, port: int, employees: int, delay: float) -> int:
    """Tinh huong A: su co ung dung luc 7h sang thu Hai.

    200 nhan vien cung dang nhap; ung dung loi khien phien dau tien tra FAILED,
    thu lai thi OK. Moi nguoi mot IP rieng.

    Ket qua CHO DOI (xem docs/bao-ve-hoi-dong.md, tinh huong A):
      - 100111 no <employees> lan, 100110 no <employees> lan  -> nhieu nen
      - 100120 KHONG no (moi nguoi chi sai 1 lan, can 6 lan cung user cung IP)
      - 100121 KHONG no (moi nguoi mot IP, can 8 user cung MOT IP)
      - brute_force_then_success KHONG no (stage 1 doi 100120/100121, khong phai 100111)
    """
    sent = 0
    for i in range(employees):
        user = f"{random.choice(STAFF)}{i}"
        srcip = lan_ip()
        sent += _send(sock, host, port, ERP_HOST, ERP_TAG, ev_login_typo(user, srcip))
        sent += _send(sock, host, port, ERP_HOST, ERP_TAG, ev_login_ok(user, srcip))
        time.sleep(delay)
    return sent


def _send(sock, host: str, port: int, log_host: str, tag: str, message: str) -> int:
    line = syslog_line(log_host, tag, message)
    if sock:
        sock.sendto(line.encode(), (host, port))
    else:
        print(line)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Sinh luu luong lanh tinh de do false positive")
    parser.add_argument("--host", default="127.0.0.1", help="IP cua Wazuh manager")
    parser.add_argument("--port", type=int, default=514, help="cong syslog UDP")
    parser.add_argument(
        "--profile",
        choices=["office", "nightly", "both"],
        default="office",
        help="office = ngay lam viec; nightly = job ETL; both = ca hai",
    )
    parser.add_argument("--storm", action="store_true", help="tinh huong A: bao alert")
    parser.add_argument("--employees", type=int, default=200, help="so nhan vien cho --storm")
    parser.add_argument("--duration", type=int, default=600, help="giay chay cho profile office")
    parser.add_argument("--runs", type=int, default=20, help="so lan xuat cho profile nightly")
    parser.add_argument("--delay", type=float, default=0.5, help="giay giua cac su kien")
    parser.add_argument("--print-only", action="store_true", help="chi in, khong gui")
    args = parser.parse_args()

    started = datetime.now()
    print(f"Bat dau: {started:%Y-%m-%d %H:%M:%S}")
    print("MOI alert sinh ra trong khoang thoi gian nay deu la DUONG TINH GIA.\n")

    sock = None if args.print_only else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        if args.storm:
            print(f"Che do --storm: {args.employees} nhan vien dang nhap cung luc\n")
            sent = profile_storm(sock, args.host, args.port, args.employees, args.delay)
        else:
            if args.profile in ("office", "both"):
                print(f"Profile 'office': chay {args.duration}s\n")
                sent += profile_office(sock, args.host, args.port, args.duration, args.delay)
            if args.profile in ("nightly", "both"):
                print(f"Profile 'nightly': {args.runs} lan xuat / tai khoan dich vu\n")
                sent += profile_nightly(sock, args.host, args.port, args.runs, args.delay)
    except KeyboardInterrupt:
        print("\nDung theo yeu cau nguoi dung.")
    finally:
        if sock:
            sock.close()

    ended = datetime.now()
    print(f"\nDa gui {sent} su kien lanh tinh.")
    print(f"Khoang thoi gian: {started:%Y-%m-%dT%H:%M:%S} -> {ended:%Y-%m-%dT%H:%M:%S}")
    print("\nDem alert sinh ra trong khoang nay (tat ca deu la FP):")
    print(
        f"  python scripts/eval_detection.py --fp-window "
        f"'{started:%Y-%m-%dT%H:%M:%S}' '{ended:%Y-%m-%dT%H:%M:%S}'"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
