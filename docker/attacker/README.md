# May tan cong gia lap (attacker bot)

Container Kali dong vai "bot" cua ke tan cong trong mang doanh nghiep, dung de
kiem thu kha nang phat hien cua SIEM. **Chi chay trong lab do an.**

## Khoi dong

Stack SIEM + cac endpoint phai chay truoc (chung mang `siem-raw_default`).

```bash
docker compose -f docker/attacker/docker-compose.yml up -d --build
```

## Cong cu / kich ban (trong /opt/attack)

| Script | Tac dung | Rule kich hoat |
|--------|----------|----------------|
| `recon.sh [may...]`   | nmap quet cong cac endpoint | recon |
| `spray.sh <may> [n]`  | Password spray SSH (n luot sai/user) | 5710, 5712, 5551 |
| `brute.sh <may>`      | hydra brute-force SSH | 5710, 5712 |
| `full-attack.sh <may> <user> <pass>` | recon -> brute -> login thanh cong | 40112 + tuong quan `brute_force_then_success` |

`users.txt` / `passwords.txt` la wordlist. `passwords.txt` co san mat khau dung
(`Ketoan@123`, `Nvhung@123`, `Endpoint123!`) de kich ban "vao duoc" chay den cung.

## Chay tan cong

```bash
# Chuoi day du vao 1 may
docker exec attacker /opt/attack/full-attack.sh fs01 ketoan1 'Ketoan@123'

# Chi spray (chac chan sinh nhieu Failed password)
docker exec attacker /opt/attack/spray.sh pc01 8

# Recon toan bo
docker exec attacker /opt/attack/recon.sh erp01 fs01 pc01
```

## Kiem tra ket qua

```bash
# Alert Wazuh tu IP attacker
curl -sk -u admin:SecretPassword \
  'https://localhost:9200/wazuh-alerts-*/_search' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"data.srcip":"<IP_attacker>"}}}'

# Alert tuong quan
curl -sk -u admin:SecretPassword \
  'https://localhost:9200/siem-correlated-*/_search?pretty' \
  -d '{"query":{"term":{"correlation_rule":"brute_force_then_success"}}}'
```

Tren dashboard: index pattern `wazuh-alerts-*` (rule 5710/5712/40112) va
`siem-correlated-*` (chuoi tan cong).

## Ghi chu

- IP attacker = IP container `attacker` trong mang Docker (thuong `172.19.0.x`).
  Xem bang: `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' attacker`
- Wazuh 4.9.2 **khong phat rule 5715** cho "Accepted password"; su kien dang nhap
  thanh cong duoc gan **40112** ("failures followed by a success"), da co san
  `data.srcip` + `data.dstuser`. Vi vay stage "dang nhap thanh cong" cua rule
  tuong quan da them 40112 (xem `correlation/rules/smb_attack_chain.yml`).

## Leo thang quyen (privesc.sh)

Kich ban: dung tai khoan da chiem (`ketoan1`) -> `sudo` len root -> ghi backdoor
vao file cau hinh. Kich hoat chuoi rule tuong quan `privilege_then_config_change`:

| Giai doan | Hanh dong | Rule |
|-----------|-----------|------|
| 1. Leo quyen | `sudo -S id` / `cat /etc/shadow` | 5402 (sudo to root), 5403 (first sudo) |
| 2. Cam chot  | ghi `/etc/erpapp/config.conf`, `cron.evil` | 550/554 (syscheck FIM) |

```bash
docker exec attacker /opt/attack/privesc.sh fs01 ketoan1 'Ketoan@123'
```

Yeu cau tren endpoint muc tieu (da bake san trong image tu ban nay):
- `ketoan1` co quyen `sudo` (mo phong cau hinh sai).
- Thu muc `/etc/erpapp` duoc FIM giam sat **realtime** - chen
  `config/fim-realtime.xml` vao `<syscheck>` cua agent (xem agents/README.md §8).

**Luu y thu tu thoi gian:** script `sleep 8` giua buoc leo quyen va buoc sua config.
Alert sudo di qua auth.log tre hon FIM realtime ~1s; neu sua file ngay, timestamp
FIM co the nho hon timestamp sudo khien rule tuong quan (kiem tra thu tu
giai_doan1.first <= giai_doan2.last) khong khop.
