#!/bin/bash
# Recon: quet cong cac endpoint. Sinh nhieu ket noi -> firewall/agent ghi log.
set -u
TARGETS="${*:-erp01 fs01 pc01}"
echo "[recon] quet cong: $TARGETS"
for t in $TARGETS; do
    echo "=== nmap $t ==="
    nmap -Pn -sS -T4 --top-ports 100 "$t"
done
