#!/bin/bash
# Password spray: nhieu user, moi user vai lan sai -> nhieu "Failed password".
# Dam bao co du su kien du hydra dung khi tim thay mat khau dung.
set -u
TARGET="${1:-fs01}"
ATTEMPTS="${2:-8}"
echo "[spray] SSH spray -> $TARGET ($ATTEMPTS luot/user)"
while read -r u; do
    for i in $(seq 1 "$ATTEMPTS"); do
        sshpass -p "wrongpass$i" ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=3 -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no "$u@$TARGET" exit 2>/dev/null
    done
done < /opt/attack/users.txt
echo "[spray] xong"
