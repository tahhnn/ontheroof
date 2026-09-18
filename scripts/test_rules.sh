#!/usr/bin/env bash
# Kiem thu decoder/rule tu viet bang wazuh-logtest trong container manager.
# Chay: bash scripts/test_rules.sh
set -euo pipefail

CONTAINER="${CONTAINER:-siem-raw-wazuh.manager-1}"

samples=(
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=FAILED user=nvhung srcip=192.168.10.24 reason=bad_password path=/api/login'
  'Aug 25 13:40:20 erp01 erpapp: AUTH result=OK user=nvhung srcip=192.168.10.24 reason=none path=/api/login'
  'Aug 25 13:41:55 erp01 erpapp: EXPORT rows=25000 module=customer user=nvhung srcip=192.168.10.24 file=khachhang.csv'
  'Aug 25 13:42:03 erp01 erpapp: PERM action=grant role=admin target=ketoan1 user=nvhung srcip=192.168.10.24'
  'Aug 25 13:43:19 erp01 erpapp: TXN action=update_price order=DH20260825 old=1200000 new=1000 user=nvhung srcip=192.168.10.24'
  # Log firewall dinh dang iptables - decoder co san cua Wazuh, ra rule 100200 (level 2).
  'Aug 25 13:44:02 fw01 kernel: [12345.678901] IPTABLES-DROP: IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=203.0.113.77 DST=192.168.10.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=44321 DPT=3389 WINDOW=1024 RES=0x00 SYN URGP=0'

  # ===== Ca hoi quy - 4 loi da vap, dung xoa =====
  # Ky vong ghi ngay sau moi dong; doi chieu bang mat khi chay script.

  # (1) status phai neo ^OK$ / ^FAILED$. Khong neo la so khop chuoi con => "NOTOK"
  #     bi xep vao dang nhap THANH CONG, lam rule tuong quan ket luan nguoc.
  #     Ky vong: 100101 (KHONG duoc ra 100110)
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=NOTOK user=x srcip=1.1.1.1 reason=none path=/l'
  #     Ky vong: 100101 (KHONG duoc ra 100111)
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=FAILED_OK user=x srcip=1.1.1.1 reason=none path=/l'

  # (2) Nguong 10000 dong phai so bang so, khong dem chu so.
  #     Ky vong: 100130 (KHONG duoc ra 100131)
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=00012 module=customer user=u srcip=1.1.1.1 file=a.csv'
  #     Ky vong: 100130
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=9999 module=customer user=u srcip=1.1.1.1 file=a.csv'
  #     Ky vong: 100131 - neu ra 100130 tuc la mat type="pcre2", os_regex khong hieu [1-9]
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=10000 module=customer user=u srcip=1.1.1.1 file=a.csv'

  # (3) Dong log hong phai roi vao 100101, khong duoc bien mat vao 100100 level 0.
  #     Ky vong: 100101 - thieu field file=
  'Aug 25 13:40:12 erp01 erpapp: EXPORT rows=25000 module=customer user=u srcip=1.1.1.1'
  #     Ky vong: 100101 - doi thu tu field
  'Aug 25 13:40:12 erp01 erpapp: AUTH user=nvhung result=OK srcip=1.1.1.1 reason=none path=/l'
  #     Ky vong: 100101 - gia tri co khoang trang
  'Aug 25 13:40:12 erp01 erpapp: AUTH result=FAILED user=nv hung srcip=1.1.1.1 reason=bad password path=/l'
)

for line in "${samples[@]}"; do
  printf '\n\033[1;34m==> %s\033[0m\n' "$line"
  # MSYS_NO_PATHCONV=1: tren Git Bash (Windows), duong dan /var/ossec/... bi doi thanh
  # C:/Program Files/Git/var/ossec/... khien docker exec bao "no such file or directory",
  # loi lai bi "|| true" nuot mat nen script chay im lang ma khong in gi.
  # Bien nay vo hai tren Linux/WSL.
  # Khong dung co -q: o Wazuh 4.9 no chan luon phan ket qua decode/rule, script se im lang.
  printf '%s\n' "$line" | MSYS_NO_PATHCONV=1 docker exec -i "$CONTAINER" /var/ossec/bin/wazuh-logtest 2>&1 \
    | grep -E 'decoder|id:|level:|description|dstuser|srcip|No decoder|Phase' || true
done
