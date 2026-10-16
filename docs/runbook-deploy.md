# Runbook triển khai SIEM-raw lên VPS (đợt chạy liên tục 25 ngày)

> Runbook là danh sách thao tác **theo thứ tự**, mỗi bước có lệnh, kết quả mong đợi và cách xử lý khi sai. Giải thích "vì sao" nằm ở `docs/so-tay-van-hanh.md` mục 9; runbook chỉ dẫn chiếu sang đó.
>
> Trạng thái: **chưa chạy trọn vẹn trên VPS thật**. Bước ghi *(chưa kiểm chứng)* phải xác nhận khi chạy; lỗi mới gặp ghi vào mục 8 của sổ tay theo mẫu đang có.

## 0. Thông tin chung

| Mục | Giá trị |
|-----|---------|
| Mục tiêu | Chạy stack liên tục 25 ngày, thu số liệu cho chương 5: Recall + độ trễ, FP theo ngày, RAM/CPU/đĩa, độ ổn định |
| Phạm vi | Phương án A (stack + 3 endpoint container + attacker trên VPS). Phương án B (agent thật ở xa) tuỳ chọn, bước E4 |
| Cấu hình VPS | 4 vCPU, 8 GB RAM, 80 GB SSD, Ubuntu 22.04/24.04, loại KVM (sổ tay 9.1) |
| Phiên bản | Wazuh 4.9.2 (`WAZUH_VERSION` trong `docker/single-node/.env`) |
| Thời gian dựng | Khoảng 2–3 giờ cho bước A → H |
| Quy ước | Mọi lệnh chạy **trên VPS, từ thư mục gốc repo** (`~/SIEM-raw`), trừ khi ghi khác |

Ghi mọi mốc giờ vào **Nhật ký triển khai** (mục 9) ngay khi làm. Cửa sổ đo FP dựa vào các mốc này.

## 1. Go / No-go trước khi bắt đầu

Làm trên laptop. Thiếu một mục thì **dừng**.

- [ ] Mọi thay đổi đã push lên `origin/main` (VPS clone từ GitHub): `git status -sb` hiện `## main...origin/main`, không có `ahead`.
- [ ] Log nền không tự sinh cảnh báo giả: `python docker/agents/scripts/app-logger.py --audit 25` → dòng cuối `log nen khong kich hoat rule tan cong nao`.
- [ ] Unit test engine: `(cd correlation && python -m pytest -q)` → toàn bộ pass.
- [ ] Đã có VPS, đăng nhập SSH bằng key được.
- [ ] Firewall **của nhà cung cấp** (không phải UFW): chỉ mở `22/tcp` cho IP nhà/trường. Mở thêm `1514/tcp`, `1515/tcp` chỉ khi làm phương án B.
- [ ] Bản local trên laptop vẫn chạy được: dự phòng ngày bảo vệ (sổ tay 9.11).

## 2. Giai đoạn A — Chuẩn bị VPS

```bash
# A1. Docker + Compose plugin
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"      # đăng xuất rồi SSH lại
docker compose version               # >= 2.24.4 (cần cho thẻ !override)

# A2. Indexer cần vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf

# A3. Swap 4 GB
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab

# A4. Công cụ cho script đo (measure_capacity.sh gọi lệnh `python`)
sudo apt-get install -y git python3 python3-requests python-is-python3

# A5. Giới hạn log container. LƯU Ý: lệnh tee GHI ĐÈ daemon.json; nếu file đã có thì sửa tay
cat /etc/docker/daemon.json 2>/dev/null
echo '{"log-driver":"json-file","log-opts":{"max-size":"50m","max-file":"3"}}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker

# A6. Đồng hồ
timedatectl | grep synchronized
```

| Kiểm tra | Mong đợi | Nếu sai |
|----------|----------|---------|
| `docker compose version` | `v2.24.4` trở lên | Cài lại plugin từ repo Docker, không dùng `docker-compose` v1 |
| `sysctl vm.max_map_count` | `262144` | VPS loại OpenVZ/LXC không cho đổi → đổi sang VPS KVM |
| `free -h` | Swap 4.0Gi | Chạy lại A3 |
| `timedatectl` | `System clock synchronized: yes` | `sudo timedatectl set-ntp true`. Lệch giờ làm sai cửa sổ tương quan và khung giờ rule 100122 |
| `docker info --format '{{.LoggingDriver}}'` | `json-file` và không lỗi | Sai cú pháp `daemon.json` thì Docker không khởi động: `sudo journalctl -u docker -n 20` |

## 3. Giai đoạn B — Lấy code và cấu hình riêng VPS

```bash
# B1. Code
git clone https://github.com/tahhnn/ontheroof.git ~/SIEM-raw && cd ~/SIEM-raw
git log --oneline -1                  # ghi commit vào nhật ký

# B2. Không để lỡ commit mật khẩu thật từ VPS
git update-index --skip-worktree docker/single-node/.env docker/single-node/config/wazuh_indexer/internal_users.yml

# B3. Bật lớp ghi đè VPS (bind port quản trị vào 127.0.0.1)
echo "COMPOSE_FILE=docker-compose.yml:docker-compose.vps.yml" >> docker/single-node/.env

# B4. ossec.conf có mật khẩu enroll
sed 's#<use_password>no</use_password>#<use_password>yes</use_password>#' \
  docker/single-node/config/wazuh_manager/ossec.conf > docker/single-node/config/wazuh_manager/ossec.vps.conf
openssl rand -hex 16 > docker/single-node/config/wazuh_manager/authd.pass

# B5. Gói agent cho 3 endpoint container (mount từ gốc repo)
curl -fsSLO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb
```

| Kiểm tra | Mong đợi | Nếu sai |
|----------|----------|---------|
| `grep use_password docker/single-node/config/wazuh_manager/ossec.vps.conf` | `yes` | Chạy lại B4 |
| `(cd docker/single-node && docker compose config \| grep -B1 -A3 published)` | `9200`, `443`, `55500`, `514` có `host_ip: 127.0.0.1`; chỉ `1514`, `1515` không có | Thiếu dòng `COMPOSE_FILE` trong `.env`, hoặc Compose cũ hơn 2.24.4 |
| `ls -l wazuh-agent_4.9.2-1_amd64.deb` | File khoảng 10 MB | **Phải có trước bước E1.** Thiếu file thì Docker tạo một *thư mục* cùng tên để mount, `dpkg -i` thất bại |

Ghi lại nội dung `authd.pass` vào trình quản lý mật khẩu. **Không** dán vào tài liệu hay chat.

## 4. Giai đoạn C — Dựng stack

```bash
bash scripts/deploy.sh
```

`deploy.sh` sinh chứng chỉ, chạy `docker compose up -d` bên trong `docker/single-node/` (nên nhận `COMPOSE_FILE`), nạp security index bằng `securityadmin.sh`, rồi khởi động lại manager và correlator.

| Kiểm tra | Mong đợi | Nếu sai |
|----------|----------|---------|
| `(cd docker/single-node && docker compose ps)` | 4 container `running`: manager, indexer, dashboard, correlator | `docker compose logs --tail=50 <service>`, đối chiếu sổ tay mục 7–8 |
| `sudo ss -tulpn \| grep -E ':(443\|514\|1514\|1515\|9200\|55500)\b'` | `9200`, `443`, `55500`, `514` ở `127.0.0.1`; chỉ `1514`, `1515` ở `0.0.0.0` | **Dừng ngay**, Indexer đang phơi ra internet. Chạy lại `(cd docker/single-node && docker compose up -d)`, không dùng `-f` từ thư mục gốc (sổ tay 9.6) |
| `curl -sk -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health?pretty` | `"status" : "green"` hoặc `"yellow"` | `503 Security not initialized` → sổ tay 8.1 |
| `(cd docker/single-node && docker compose logs --tail=5 correlator)` | Có dòng `Vong quet xong` | `401` → sai `INDEXER_PASSWORD`; `Cho Wazuh Indexer...` kéo dài → Indexer chưa lên |
| `openssl x509 -enddate -noout -in docker/single-node/config/certs/root-ca.pem` | Ngày hết hạn sau ngày kết thúc đợt chạy | Sinh lại chứng chỉ trước khi tiếp tục |

## 5. Giai đoạn D — Đổi mật khẩu mặc định

*(Quy trình chưa kiểm chứng trên repo này — sổ tay 9.5.)* Port quản trị đã bind `127.0.0.1` nên đây là lớp bảo vệ thứ hai, không phải lớp duy nhất.

```bash
# D1. Sinh hash
docker exec siem-raw-wazuh.indexer-1 bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "<MAT-KHAU-MOI>"'
```

- D2. Thay dòng `hash:` của user `admin` trong `docker/single-node/config/wazuh_indexer/internal_users.yml`.
- D3. Sửa `INDEXER_PASSWORD` trong `docker/single-node/.env`.
- D4. `bash scripts/deploy.sh` (nạp lại user, tạo lại container có biến môi trường đổi).
- D5. Lặp lại với `kibanaserver` ↔ `DASHBOARD_PASSWORD` nếu muốn.

Mật khẩu có ký tự đặc biệt (`$`, `` ` ``, `"`, khoảng trắng) dễ vỡ khi đọc qua `.env` và shell. Nên dùng chữ + số dài.

Từ đây, script đo chạy trên VPS cần biến môi trường:

```bash
export INDEXER_PASSWORD="$(grep '^INDEXER_PASSWORD=' docker/single-node/.env | cut -d= -f2-)"
```

| Kiểm tra | Mong đợi | Nếu sai |
|----------|----------|---------|
| `curl -sk -u "admin:$INDEXER_PASSWORD" https://127.0.0.1:9200/` | JSON có `"cluster_name"` | `401` → hash sai hoặc `securityadmin.sh` chưa chạy lại |
| `curl -sk -u admin:SecretPassword https://127.0.0.1:9200/` | `401` | Mật khẩu cũ vẫn dùng được → D2 chưa có hiệu lực |
| Log correlator | Không có `401` | `(cd docker/single-node && docker compose up -d correlator)` để nhận `.env` mới |

## 6. Giai đoạn E — Endpoint và agent

```bash
# E1. Ba endpoint + attacker (không publish port nên dùng -f từ gốc được)
docker compose -f docker/agents/docker-compose.yml up -d --build
docker compose -f docker/attacker/docker-compose.yml up -d --build

# E2. Cài agent có mật khẩu enroll — biến WAZUH_REGISTRATION_PASSWORD (chưa kiểm chứng)
PASS=$(cat docker/single-node/config/wazuh_manager/authd.pass)
for h in erp01 fs01 pc01; do
  docker exec -e PASS="$PASS" -e H="$h" "$h" bash -c 'WAZUH_MANAGER=wazuh.manager WAZUH_AGENT_NAME="$H" WAZUH_REGISTRATION_PASSWORD="$PASS" dpkg -i /opt/wazuh-agent.deb && /var/ossec/bin/wazuh-control start'
done

# E3a. erp01 đọc log ERP
docker cp docker/agents/config/erp01-localfile.xml erp01:/tmp/lf.xml
docker exec erp01 python3 -c "cfg='/var/ossec/etc/ossec.conf'; s=open(cfg).read(); a=open('/tmp/lf.xml').read(); i=s.rfind('</ossec_config>'); open(cfg,'w').write(s[:i]+a+s[i:])"
docker exec erp01 /var/ossec/bin/wazuh-control restart

# E3b. fs01 bật FIM realtime cho /etc/erpapp (rule privilege_then_config_change)
docker exec fs01 bash -c '
  grep -q "/etc/erpapp" /var/ossec/etc/ossec.conf || \
  sed -i "s|<directories>/etc,/usr/bin,/usr/sbin</directories>|&\n    <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">/etc/erpapp</directories>|" /var/ossec/etc/ossec.conf'
docker exec fs01 /var/ossec/bin/wazuh-control restart
```

E4 *(tuỳ chọn, phương án B)*: agent thật trỏ về IP public của VPS, theo sổ tay 9.8. Nếu cài agent `vps-host` trên chính VPS, nhớ loại nó khỏi phép đo FP (`--exclude-entity vps-host`).

| Kiểm tra | Mong đợi | Nếu sai |
|----------|----------|---------|
| `docker exec siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l` | `erp01`, `fs01`, `pc01` ở trạng thái `Active` | `docker exec <may> tail -20 /var/ossec/logs/ossec.log`. Lỗi mật khẩu enroll → sổ tay 9.9 dòng 1. Lỗi `Invalid user '' or group 'wazuh'` → `docker/agents/README.md` mục 7 |
| `docker exec erp01 grep "Analyzing file" /var/ossec/logs/ossec.log` | Có `/var/log/erpapp/app.log` | Chạy lại E3a, kiểm tra thẻ `<localfile>` nằm trước `</ossec_config>` cuối |
| `docker exec erp01 sh -c 'grep -l "app-logge[r]" /proc/[0-9]*/cmdline \| wc -l'` | `1` trở lên | `docker restart erp01` (entrypoint tự chạy lại app-logger) |
| `docker exec fs01 grep "Directory set for real time" /var/ossec/logs/ossec.log` | Có `/etc/erpapp` | Chạy lại E3b |
| Sau ~1 phút: `curl -sk -u "admin:$INDEXER_PASSWORD" "https://127.0.0.1:9200/wazuh-alerts-*/_count?q=agent.name:erp01"` | `count` > 0 (trong giờ hành chính; ban đêm app-logger gần như im) | `docker exec siem-raw-wazuh.manager-1 filebeat test output` |

## 7. Giai đoạn F — Dashboard

Từ **laptop**, mở tunnel (giữ cửa sổ này suốt phiên làm việc):

```bash
ssh -N -L 8443:127.0.0.1:443 -L 9200:127.0.0.1:9200 user@<IP-VPS>
```

- F1. Mở `https://localhost:8443`, đăng nhập `admin`.
- F2. **Dashboards Management → Saved objects → Import** → chọn `dashboards/siem-correlated-dashboard.ndjson` (file đã có sẵn trong repo; chỉ chạy lại `python dashboards/build_dashboard.py` nếu có sửa script).

| Kiểm tra | Mong đợi | Nếu sai |
|----------|----------|---------|
| Đăng nhập | Vào được trang chủ Wazuh | `Error getting the authorization token` → chờ manager lên xong 2–3 phút (sổ tay mục 7) |
| Mở dashboard "SIEM-raw - Alert tuong quan" | Hiện các panel (có thể chưa có dữ liệu) | Index pattern `siem-correlated-*` chưa có index → chạy bước G2 trước rồi tải lại |

## 8. Giai đoạn G + H — Kiểm thử chấp nhận và bật giám sát

```bash
# G1. Đo năng lực lần 1 (trên stack còn sạch)
mkdir -p data/results
bash scripts/measure_capacity.sh --endpoints 50 --retention 90 | tee data/results/capacity-day0.txt

# G2. Recall + độ trễ lần 1
python3 scripts/eval_detection.py --recall | tee data/results/recall-day0.txt

# G3. Một chuỗi tấn công thật qua attacker container (ghi giờ bắt đầu/kết thúc)
docker exec -it attacker /opt/attack/full-attack.sh fs01
```

- G4. Chụp ảnh dashboard sau G2/G3 cho chương 5.
- G5. Ghi **giờ kết thúc của kịch bản tấn công cuối cùng** vào nhật ký. Cửa sổ FP bắt đầu **2 giờ sau** mốc này (rule có cửa sổ dài nhất là `privilege_then_config_change`, 7200 giây).

```bash
# H1. Chụp sức khoẻ 30 phút một lần
bash scripts/health_snapshot.sh            # chạy tay trước: phải ra một dòng đủ trường, không có NA
( crontab -l 2>/dev/null; echo "*/30 * * * * cd $HOME/SIEM-raw && bash scripts/health_snapshot.sh >/dev/null 2>&1" ) | crontab -
crontab -l
```

**Tiêu chí chấp nhận — đạt hết mới bắt đầu tính 25 ngày:**

- [ ] 4 container stack + 3 endpoint `running`; 3 agent `Active`.
- [ ] Port quản trị chỉ ở `127.0.0.1` (bước C).
- [ ] `recall-day0.txt` có kết quả cho từng kịch bản (ghi lại kịch bản nào trượt, không sửa số).
- [ ] `health_snapshot.sh` chạy tay ra đủ trường; `crontab -l` có dòng mới.
- [ ] Nhật ký đã ghi: commit, giờ kết thúc tấn công, giờ bắt đầu cửa sổ FP.

## 9. Vận hành 25 ngày

### Lịch

| Giai đoạn | Việc | Không được làm |
|-----------|------|----------------|
| Ngày 0–1 | Bước A → H | — |
| Ngày 1 (+2 giờ) → ngày 23 | **Chỉ log nền** + agent. Theo dõi hằng ngày | Chạy `simulate_attack.py`, `attacker`, `benign_traffic.py`, tập demo |
| Ngày 23–25 | Bước K (đo lần 2, xuất số liệu) | — |

Lỡ chạy tấn công giữa chừng: ghi giờ bắt đầu/kết thúc vào `data/results/attack-log.txt`, chia cửa sổ FP thành nhiều đoạn (mỗi đoạn kết thúc trước giờ tấn công, đoạn sau bắt đầu 2 giờ sau khi tấn công xong), đo từng đoạn rồi cộng.

### Hằng ngày (5 phút)

```bash
tail -3 data/results/health.log
```

| Trường | Ngưỡng xử lý | Hành động |
|--------|--------------|-----------|
| `agents_active` | Nhỏ hơn số agent đã cài | `agent_control -l`, xem `ossec.log` của agent đó; `docker restart <may>` |
| `app_logger` | `0` | `docker restart erp01`. Ghi giờ phát hiện: khoảng log nền chết không tính vào số ngày đo FP |
| `heap_pct` | > 85 | Indexer sắp hết heap. Ghi lại, cân nhắc tăng `-Xmx` (phải tạo lại container indexer, ghi vào nhật ký) |
| `disk` | > 80% | `curl -sk -u "admin:$INDEXER_PASSWORD" "https://127.0.0.1:9200/_cat/indices?v&s=store.size:desc" \| head` |
| `containers` | `RestartCount` tăng so với hôm trước | `docker logs --tail=100 <container>`; ghi giờ restart vào nhật ký (là số liệu độ ổn định) |
| Không có dòng mới hôm nay | — | Cron không chạy: `crontab -l`, `grep CRON /var/log/syslog \| tail` |

### Hằng tuần

```bash
# Trên laptop: kéo số liệu về, phòng VPS hỏng volume
scp -r user@<IP-VPS>:SIEM-raw/data/results ./data/results-vps-$(date +%F)
```

Đồng thời đo FP tạm tính cho tuần vừa qua (trên VPS):

```bash
python3 scripts/eval_detection.py --fp-window '<bat dau tuan>' '<ket thuc tuan>' --exclude-entity vps-host
```

FP tuần khác 0 thì đọc cột "Doi tuong bi bao nham", tìm nguyên nhân **trước khi** đợt chạy kết thúc. Không sửa rule giữa chừng; nếu buộc phải sửa thì ghi giờ sửa, số liệu trước/sau là hai đợt đo khác nhau.

## 10. Giai đoạn K — Kết thúc đợt

```bash
# K1. Đo FP toàn bộ cửa sổ (mốc lấy từ nhật ký)
python3 scripts/eval_detection.py --fp-window '<bat dau FP>' '<ket thuc FP>' --exclude-entity vps-host | tee data/results/fp-window.txt

# K2. Năng lực lần 2: so với day0 để thấy dung lượng tăng sau 3 tuần
bash scripts/measure_capacity.sh --endpoints 50 --retention 90 | tee data/results/capacity-day25.txt

# K3. Recall lần 2: hệ thống còn bắt được sau 3 tuần chạy liên tục?
python3 scripts/eval_detection.py --recall | tee data/results/recall-day25.txt

# K4. Tổng hợp chỉ số (TP/FN lấy từ K3, FP từ K1, số giờ = độ dài cửa sổ FP)
python3 scripts/eval_detection.py --report --tp <TP> --fn <FN> --fp <FP> --hours <GIO> --endpoints 3
```

- K5. Kéo `data/results/` về laptop (lệnh `scp` ở mục 9), commit vào repo.
- K5b. Trên laptop: `pip install matplotlib` rồi `python scripts/plot_health.py` → `data/results/health.png` (RAM, heap, disk, alert tích luỹ, alert/ngày) và bảng độ sẵn sàng, khoảng `app_logger=0`, agent giảm, lần restart in ra stdout (`| tee data/results/health-summary.txt`); thử trước bằng `--selftest`.
- K6. Ghi vào báo cáo kèm **điều kiện đo**: FP đo trên log nền do chính đồ án sinh ra (`app-logger`), Recall đo trên kịch bản do chính đồ án viết; 3 endpoint, không phải quy mô SMB thật; số cho 50 endpoint là ngoại suy.
- K7. Giữ stack chạy tới ngày bảo vệ nếu còn dùng để demo; nếu không thì `crontab -r` (xoá **toàn bộ** crontab của user, kiểm tra `crontab -l` trước) và dừng stack.

## 11. Rollback và sự cố

| Tình huống | Xử lý |
|------------|-------|
| Port quản trị phơi ra `0.0.0.0` | `(cd docker/single-node && docker compose up -d)` để tạo lại container với lớp ghi đè; kiểm tra lại bằng `ss` (bước C) |
| Đổi mật khẩu (D) làm hỏng đăng nhập | `git checkout docker/single-node/config/wazuh_indexer/internal_users.yml` (gỡ `--skip-worktree` trước: `git update-index --no-skip-worktree <file>`), trả `INDEXER_PASSWORD` về giá trị cũ, `bash scripts/deploy.sh` |
| Manager không lên sau khi sửa rule | `wazuh-control restart` từ chối ruleset lỗi và giữ tiến trình cũ; stop+start thì mọi dịch vụ chết. Sửa file trong `custom/`, kiểm tra bằng `wazuh-logtest` trước khi restart (skill `wazuh-rule`) |
| VPS khởi động lại | Docker tự bật container (`restart: always` / `unless-stopped`); agent trong endpoint tự bật lại. Kiểm tra bảng ở bước E. Ghi giờ vào nhật ký: correlator tắt lâu hơn cửa sổ rule thì bỏ sót finding trong khoảng đó |
| Đĩa đầy | Xoá index cũ nhất của `wazuh-alerts-*` (ghi lại vì mất dữ liệu đo), sổ tay mục 7 |
| Dựng lại từ đầu | `(cd docker/single-node && docker compose down -v)` **xoá toàn bộ dữ liệu**. Chỉ làm khi đã kéo `data/results/` về laptop |

## 12. Nhật ký triển khai

Chép bảng này vào `data/results/deploy-log.md` trên VPS và điền khi làm.

| Thời điểm (giờ VN) | Bước | Kết quả / ghi chú |
|--------------------|------|-------------------|
| | B1 — commit triển khai | |
| | C — stack lên, 4 container running | |
| | E — 3 agent Active | |
| | G5 — kết thúc kịch bản tấn công cuối | |
| | **Bắt đầu cửa sổ FP** (G5 + 2 giờ) | |
| | H1 — cron health_snapshot bật | |
| | Sự cố / restart / sửa cấu hình (mỗi lần một dòng) | |
| | **Kết thúc cửa sổ FP** | |
| | K — đo lần 2 xong, số liệu đã kéo về | |
