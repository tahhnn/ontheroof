# Sổ tay vận hành SIEM-raw

Dành cho người phụ trách CNTT của doanh nghiệp — không giả định có kiến thức chuyên sâu về SIEM.

## 1. Việc làm hằng ngày (5–10 phút)

1. Mở `https://<IP-server>` → đăng nhập.
2. Vào **Dashboard "SIEM-raw - Alert tương quan"**, xem khung 24h:
   - Có alert `critical` không? → xử lý ngay theo mục 3.
   - Có alert `high` không? → xử lý trong ngày.
3. Vào **Agents**: kiểm tra máy nào ở trạng thái `Disconnected` quá 24h → agent chết hoặc máy tắt.
4. Vào **Vulnerabilities**: xem lỗ hổng mức Critical mới xuất hiện.

## 2. Việc làm hằng tuần

- Kiểm tra dung lượng đĩa: `docker system df` và `df -h`.
- Xem **Security Configuration Assessment** để biết máy nào lệch chuẩn cấu hình.
- Rà soát alert bị lặp lại nhiều mà không phải tấn công → tinh chỉnh ngưỡng rule (mục 5).
- Sao lưu cấu hình: thư mục `custom/`, `correlation/rules/`, `docker/single-node/config/`.

## 3. Quy trình xử lý sự cố

| Alert | Ý nghĩa | Việc cần làm |
|-------|---------|--------------|
| `brute_force_then_success` | Tài khoản nhiều khả năng đã bị chiếm | Khoá tài khoản, đổi mật khẩu, kiểm tra IP nguồn, xem tài khoản đã làm gì sau khi đăng nhập |
| `account_takeover_to_exfil` | Đã bị lấy dữ liệu | Khoá tài khoản, xác định file đã xuất, báo lãnh đạo, cân nhắc nghĩa vụ thông báo theo Nghị định 13/2023 về bảo vệ dữ liệu cá nhân |
| `impossible_travel` | Tài khoản dùng chung hoặc lộ mật khẩu | Xác minh với người dùng, bắt đổi mật khẩu, bật xác thực 2 lớp |
| `mass_data_export_by_user` | Nghi ngờ nhân viên lấy dữ liệu | Đối chiếu với nghiệp vụ thật, phối hợp nhân sự |
| `scan_then_login_attempt` | Có người dò từ ngoài vào | Chặn IP tại firewall biên, rà soát dịch vụ đang mở ra Internet |
| `privilege_then_config_change` | Leo thang đặc quyền | Kiểm tra ai được cấp quyền, có đúng quy trình không |
| `noisy_agent_high_severity` | Máy nghi nhiễm mã độc hoặc rule chưa tinh chỉnh | Cô lập máy nếu nghi nhiễm, quét mã độc |

Mỗi sự cố cần ghi lại: thời điểm phát hiện, alert nào, đối tượng liên quan, hành động đã làm, kết quả.

## 4. Lệnh thường dùng

```bash
docker compose -f docker/single-node/docker-compose.yml ps
```

```bash
docker compose -f docker/single-node/docker-compose.yml logs -f correlator
```

```bash
docker compose -f docker/single-node/docker-compose.yml restart wazuh.manager
```

```bash
docker exec -it siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Kiểm tra dung lượng index:

```bash
curl -sk -u admin:SecretPassword https://localhost:9200/_cat/indices?v
```

## 5. Tinh chỉnh khi nhiều cảnh báo giả

Alert nhiễu làm người vận hành mất phản xạ với cảnh báo thật. Cách xử lý theo thứ tự ưu tiên:

1. **Nâng ngưỡng** — sửa `frequency`/`timeframe` trong `custom/rules/local_rules.xml`, hoặc `min_count`/`window` trong `correlation/rules/*.yml`.
2. **Loại trừ có điều kiện** — thêm rule con mức 0 cho trường hợp hợp lệ đã xác minh (ví dụ máy chủ backup xuất dữ liệu định kỳ).
3. **Sửa nguồn log** — nếu ứng dụng ghi log sai gây hiểu nhầm.

Không tắt hẳn rule. Hạ mức xuống 0 và ghi chú lý do ngay trong file rule để còn truy vết được về sau.

Sau khi sửa:

```bash
docker compose -f docker/single-node/docker-compose.yml restart wazuh.manager
```

Rule tương quan được nạp lại khi correlator khởi động:

```bash
docker compose -f docker/single-node/docker-compose.yml restart correlator
```

## 6. Sao lưu và khôi phục

Cần sao lưu:

- Thư mục cấu hình: `docker/single-node/config/`, `custom/`, `correlation/rules/`
- Docker volume: `wazuh_etc`, `wazuh_api_configuration`, `wazuh-indexer-data`

```bash
docker run --rm -v siem-raw_wazuh_etc:/data -v "$PWD/backup:/backup" alpine tar czf /backup/wazuh_etc.tgz -C /data .
```

Khôi phục: dựng lại stack rồi giải nén ngược vào volume tương ứng trước khi khởi động container.

## 7. Xử lý sự cố hệ thống

| Hiện tượng | Nguyên nhân thường gặp | Cách xử lý |
|------------|------------------------|------------|
| Indexer khởi động rồi tắt | `vm.max_map_count` thấp, hoặc thiếu RAM | `sysctl -w vm.max_map_count=262144`, tăng RAM cho Docker |
| Dashboard báo lỗi kết nối API | Manager chưa lên xong | Đợi 2–3 phút, xem `logs wazuh.manager` |
| Không thấy alert mới | Filebeat lỗi hoặc chứng chỉ sai | `docker exec siem-raw-wazuh.manager-1 filebeat test output` |
| Correlator log lỗi 401 | Sai mật khẩu Indexer trong `.env` | Sửa `.env` rồi `restart correlator` |
| Đĩa đầy | Index cũ chưa xoá | Xoá index cũ hoặc cấu hình ISM policy để tự xoá sau N ngày |
| `docker ps` treo, exec vào container báo `Input/output error` | Docker Desktop / WSL2 lỗi, không phải lỗi cấu hình SIEM | Khởi động lại Docker Desktop, hoặc `wsl --shutdown` rồi mở lại |

## 8. Bốn lỗi đã gặp khi triển khai lần đầu

Ghi lại để khỏi mất thời gian lặp lại — đều đã vá sẵn trong repo.

### 8.1 `OpenSearch Security not initialized` (HTTP 503)

Lần chạy đầu, plugin security chưa tạo index `.opendistro_security` nên mọi request đều 503 và dashboard không đăng nhập được. Phải nạp cấu hình một lần:

```bash
docker exec siem-raw-wazuh.indexer-1 bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -icl -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost -p 9200'
```

`scripts/deploy.sh` đã tự chạy bước này. Lệnh chạy lại nhiều lần không gây hại.

Lưu ý: `indexer-security-init.sh` có sẵn trong image **không dùng được** ở bản Docker — nó tìm `/etc/wazuh-indexer` (đường dẫn của bản cài bằng gói RPM/DEB) và báo `ERROR: it was not possible to find /etc/wazuh-indexer`.

### 8.2 `Could not open file 'etc/shared/ar.conf'` — manager không khởi động

Nguyên nhân: bind-mount file custom **vào bên trong** named volume:

```yaml
# SAI
- ../../custom/rules/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
```

`/var/ossec/etc` là named volume `wazuh_etc`. Docker tạo sẵn thư mục cho bind-mount trước khi nạp volume, volume bị coi là "đã có dữ liệu" nên **không copy nội dung gốc từ image** — mất `etc/shared/`, `etc/lists/`, `client.keys`. `wazuh-analysisd` chết ngay khi khởi động.

Cách đúng: mount qua `/wazuh-config-mount`, script init của image sẽ `cp -r` vào đúng chỗ:

```yaml
# ĐÚNG
- ../../custom/rules/local_rules.xml:/wazuh-config-mount/etc/rules/local_rules.xml:ro
```

Nếu volume đã lỡ hỏng, phải xoá để nạp lại:

```bash
docker compose stop wazuh.manager; docker compose rm -f wazuh.manager; docker volume rm siem-raw_wazuh_etc; docker compose up -d wazuh.manager
```

### 8.3 `Invalid option 'different_dstuser' for rule '100121'`

Wazuh 4.9 chỉ chấp nhận các tuỳ chọn so khớp: `same_source_ip`, `same_user`, `same_id`, `same_location`, `same_field`, `different_field`, `different_url`. Không có `same_srcip` hay `different_dstuser`. Dùng dạng tổng quát:

```xml
<same_source_ip />
<different_field>dstuser</different_field>
```

### 8.4 `Failure to read rule 100130. Field 'extra_data' is static`

Wazuh chia trường thành hai loại:

- **Static**: `srcip`, `dstuser`, `srcuser`, `url`, `status`, `id`, `action`, `data`, `extra_data`. Trong rule phải gọi bằng thẻ riêng (`<status>`, `<srcip>`…), **không** dùng được `<field name="...">`.
- **Dynamic**: mọi tên khác do mình đặt. Gọi bằng `<field name="...">`, so khớp được bằng biểu thức.

Vì vậy các trường nghiệp vụ riêng của ứng dụng trong `local_decoder.xml` đều đặt tiền tố `erp.` để thành trường động: `erp.module`, `erp.rows`, `erp.role`, `erp.action`, `erp.order`, `erp.old_price`, `erp.new_price`, `erp.reason`, `erp.file`. Trên Indexer chúng nằm ở `data.erp.*`.

## 9. Triển khai lên VPS (phương án A + B)

> Trạng thái: **chưa chạy thử trên VPS thật**. Các bước dưới đây được soạn dựa trên cấu hình trong repo. Đã kiểm chứng trên Windows bằng `docker compose config` rằng lớp ghi đè `docker-compose.vps.yml` bind port đúng như mô tả. Những chỗ ghi *(chưa kiểm chứng)* phải xác nhận lại khi chạy thật; lỗi mới gặp thì ghi vào mục 8.

### 9.1 Hai phương án và mục đích đo

| | A — toàn bộ trên VPS | B — thêm agent thật ở xa |
|---|---|---|
| Chạy gì trên VPS | Stack, 3 endpoint `erp01/fs01/pc01`, `attacker`, correlator | Như A |
| Chạy gì ngoài VPS | Không có | Laptop Windows và/hoặc VM Linux cài agent, trỏ về IP VPS |
| Port mở ra internet | Chỉ `22` | `22`, `1514/tcp`, `1515/tcp` |
| Chứng minh được | Chạy 24/7 → đo FP theo ngày; `measure_capacity.sh` trên cấu hình cố định | Agent gửi log qua internet, qua NAT, mất kết nối rồi kết nối lại; endpoint Windows thật |
| Giới hạn | Log không rời khỏi VPS, về mặt mạng không khác lab | Custom rule hiện **không có rule Windows** (`local_rules.xml` chỉ có nhóm `erpapp`, `syslog,firewall`, `correlation`). Agent Windows chỉ kích hoạt ruleset mặc định của Wazuh |

Cấu hình VPS đề xuất: 4 vCPU, 8 GB RAM, 80 GB SSD, Ubuntu 22.04/24.04, loại KVM (không dùng OpenVZ/LXC vì cần đổi `vm.max_map_count`). Mức 2 vCPU/4 GB có thể chạy nhờ heap Indexer đặt 1 GB (`OPENSEARCH_JAVA_OPTS` trong `docker-compose.yml`), nhưng dashboard dễ bị OOM; chưa thử.

#### Sáu máy được giám sát

Mọi máy cài **cùng một gói** `wazuh-agent` 4.9.2; agent chỉ thu và gửi log, việc phát hiện nằm ở manager (decoder, `local_rules.xml`, correlator). Một agent chỉ giám sát được máy nó được cài, nên "6 agent" nghĩa là 6 máy. Các máy chỉ khác nhau ở **cấu hình đọc log**. Chọn 6 máy khác loại để log thu về đa dạng, không phải để tạo 6 loại agent.

| # | Agent | Loại máy | Cấu hình thêm | Dùng để chứng minh | Nhóm |
|---|-------|----------|---------------|--------------------|------|
| 1 | `erp01` | Container trên VPS — máy chủ ứng dụng | Đọc `/var/log/erpapp/app.log` (`docker/agents/config/erp01-localfile.xml`) | Decoder `erpapp` và rule tự viết | Demo phát hiện |
| 2 | `fs01` | Container trên VPS — file server | FIM realtime `/etc/erpapp` (`docker/agents/config/fim-realtime.xml`, xem mục 8 `docker/agents/README.md`) | Mục tiêu của `full-attack.sh fs01`: brute force SSH → leo quyền → sửa cấu hình (rule tương quan `privilege_then_config_change`) | Demo phát hiện |
| 3 | `pc01` | Container trên VPS — máy trạm nhân viên | Mặc định | Máy trạm thông thường; đồng thời dùng làm máy nguồn tấn công khi demo | Demo phát hiện |
| 4 | `vps-host` | Chính host VPS | Mặc định; cài bằng `sudo bash scripts/install-agent-linux.sh -m 127.0.0.1 -n vps-host -g vps-host -P '<authd.pass>'` *(chưa kiểm chứng)* | Tấn công SSH **thật** từ internet | Tính thực tế |
| 5 | `laptop-win` | Laptop Windows của sinh viên | Mặc định (Event Log) | Endpoint Windows; thu log qua internet; mất kết nối rồi kết nối lại (9.9) | Tính thực tế |
| 6 | Máy người quen hoặc VM Linux | Máy thật ở mạng khác | Mặc định | Endpoint sau một NAT khác. **Chỉ thu log**, không tấn công (xem 9.8) | Tính thực tế, tuỳ chọn |

Nhóm "Demo phát hiện" (1–3) là phần trình diễn trực tiếp: `simulate_attack.py` và `attacker` chỉ nhắm vào đây. `simulate_attack.py` không chạm tới endpoint nào, nó gửi log giả thẳng vào manager qua syslog UDP.

Nhóm "Tính thực tế" (4–6) làm trước và lưu bằng chứng (ảnh chụp, timestamp), không phụ thuộc vào chúng trong ngày bảo vệ.

Loại `vps-host` khỏi phép đo FP ở 9.9: alert của nó là tấn công thật từ internet, không phải cảnh báo giả.

**Giới hạn:** 6 agent không phải quy mô SMB thật (20–50 máy). Con số cho 50 endpoint lấy từ `measure_capacity.sh --endpoints 50` là **ngoại suy** từ EPS đo được, phải ghi đúng như vậy trong báo cáo.

### 9.2 Vì sao cần `docker-compose.vps.yml`

`docker-compose.yml` publish `9200`, `443`, `55500`, `514/udp` ra `0.0.0.0`. Trên laptop không sao, trên VPS thì Indexer và dashboard phơi ra internet.

**Cách sai:** chặn bằng UFW (`ufw deny 9200`). Docker publish port bằng chain iptables riêng, đi trước UFW, nên luật UFW không có tác dụng với port của container.

**Cách đúng:** bind port quản trị vào `127.0.0.1`, truy cập qua SSH tunnel. File `docker/single-node/docker-compose.vps.yml` làm việc này, đồng thời thay `ossec.conf` bằng bản bật mật khẩu enroll:

| Port | Laptop | VPS |
|------|--------|-----|
| `1514/tcp`, `1515/tcp` | `0.0.0.0` | `0.0.0.0` — cần cho agent ở xa, giới hạn bằng firewall nhà cung cấp |
| `514/udp` (syslog, không mã hoá) | `0.0.0.0` | `127.0.0.1` |
| `55500` (Wazuh API), `9200` (Indexer), `443` (dashboard) | `0.0.0.0` | `127.0.0.1` |

Lớp ghi đè được bật qua biến `COMPOSE_FILE` trong `.env` (bước 9.4), nên `scripts/deploy.sh` và lệnh `docker compose` chạy **bên trong** `docker/single-node/` tự nạp cả hai file.

Cần Docker Compose ≥ 2.24.4 (thẻ `!override`).

### 9.3 Chuẩn bị VPS

```bash
# 1. Docker + Compose plugin
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"     # đăng xuất rồi SSH lại
docker compose version              # phải >= 2.24.4

# 2. Indexer cần vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf

# 3. Swap 4 GB phòng khi RAM sát ngưỡng
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab

# 4. Công cụ cho script đo
sudo apt-get install -y git python3 python3-requests
```

Firewall **ở tầng nhà cung cấp** (security group / cloud firewall), không phải UFW:

| Port | Nguồn cho phép | Phương án |
|------|----------------|-----------|
| `22/tcp` | IP nhà / trường | A, B |
| `1514/tcp`, `1515/tcp` | IP public của nơi đặt agent thật | Chỉ B |
| Còn lại | Chặn | — |

### 9.4 Lấy code và tạo cấu hình riêng cho VPS

```bash
git clone https://github.com/tahhnn/ontheroof.git SIEM-raw && cd SIEM-raw

# .env và internal_users.yml đang được git theo dõi (giá trị demo).
# Trên VPS sẽ sửa hai file này -> báo git bỏ qua thay đổi cục bộ, tránh lỡ commit mật khẩu.
git update-index --skip-worktree docker/single-node/.env docker/single-node/config/wazuh_indexer/internal_users.yml

# Bật lớp ghi đè VPS
echo "COMPOSE_FILE=docker-compose.yml:docker-compose.vps.yml" >> docker/single-node/.env

# Bản ossec.conf có mật khẩu enroll (cả hai file đã nằm trong .gitignore)
sed 's#<use_password>no</use_password>#<use_password>yes</use_password>#' \
  docker/single-node/config/wazuh_manager/ossec.conf > docker/single-node/config/wazuh_manager/ossec.vps.conf
openssl rand -hex 16 > docker/single-node/config/wazuh_manager/authd.pass
grep use_password docker/single-node/config/wazuh_manager/ossec.vps.conf   # phải thấy "yes"
cat docker/single-node/config/wazuh_manager/authd.pass                     # ghi lại để cài agent
```

> Mỗi lần `git pull` có đổi `ossec.conf`, phải chạy lại lệnh `sed` ở trên. `ossec.vps.conf` là bản sao, không tự cập nhật.

Kiểm tra trước khi chạy — mọi port quản trị phải có `host_ip: 127.0.0.1`:

```bash
(cd docker/single-node && docker compose config | grep -B1 -A3 published)
```

### 9.5 Đổi mật khẩu mặc định

`.env` và `internal_users.yml` trong repo chứa **giá trị demo**; nếu repo công khai thì ai cũng biết. Khi port quản trị đã bind `127.0.0.1`, người ngoài không chạm được Indexer/dashboard, nhưng vẫn nên đổi mật khẩu `admin` của Indexer *(quy trình chưa kiểm chứng trên repo này)*:

```bash
# 1. Chạy stack lần đầu với mật khẩu demo để có container Indexer
bash scripts/deploy.sh

# 2. Sinh hash cho mật khẩu mới
docker exec siem-raw-wazuh.indexer-1 bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "<MAT-KHAU-MOI>"'
```

3. Thay dòng `hash:` của user `admin` trong `docker/single-node/config/wazuh_indexer/internal_users.yml` bằng hash vừa sinh.
4. Sửa `INDEXER_PASSWORD` trong `docker/single-node/.env` thành mật khẩu mới.
5. Chạy lại `bash scripts/deploy.sh`: bước `securityadmin.sh` nạp lại user, `docker compose up -d` tạo lại các container có biến môi trường thay đổi.

Làm tương tự với user `kibanaserver` ↔ `DASHBOARD_PASSWORD`. Mật khẩu Wazuh API (`API_PASSWORD`, user `wazuh-wui` trong `config/wazuh_dashboard/wazuh.yml`) đổi theo cách khác, chưa ghi vào đây; port API đã bind `127.0.0.1` nên tạm để nguyên.

### 9.6 Phương án A: chạy stack, endpoint, attacker

Luôn chạy `docker compose` của stack **bên trong** `docker/single-node/`:

- **Cách sai:** `docker compose -f docker/single-node/docker-compose.yml up -d` từ thư mục gốc. Khi có `-f`, Compose bỏ qua `COMPOSE_FILE` trong `.env` → container bị tạo lại với port publish ra `0.0.0.0`.
- **Cách đúng:** `(cd docker/single-node && docker compose up -d)`.
- **Nếu đã lỡ chạy:** chạy lại cách đúng để tạo lại container, rồi kiểm tra bằng `ss` như bên dưới.

```bash
# Stack (deploy.sh tự cd vào docker/single-node nên nhận COMPOSE_FILE)
bash scripts/deploy.sh

# Gói agent cho 3 endpoint container (mount từ gốc repo; *.deb đã nằm trong .gitignore)
curl -fsSLO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb

docker compose -f docker/agents/docker-compose.yml up -d --build
docker compose -f docker/attacker/docker-compose.yml up -d --build
```

Compose của `agents` và `attacker` không publish port nào, nên chạy bằng `-f` từ gốc không ảnh hưởng.

Cài agent trong từng container. Manager đã bật `use_password` nên **container cũng phải có mật khẩu** *(biến `WAZUH_REGISTRATION_PASSWORD` của gói .deb, chưa kiểm chứng)*:

```bash
PASS=$(cat docker/single-node/config/wazuh_manager/authd.pass)
for h in erp01 fs01 pc01; do
  docker exec -e PASS="$PASS" -e H="$h" "$h" bash -c 'WAZUH_MANAGER=wazuh.manager WAZUH_AGENT_NAME="$H" WAZUH_REGISTRATION_PASSWORD="$PASS" dpkg -i /opt/wazuh-agent.deb && /var/ossec/bin/wazuh-control start'
done
docker exec siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

`erp01` cần thêm khai báo đọc log ERP — xem `docker/agents/README.md` và `docker/agents/config/erp01-localfile.xml`.

Kiểm tra port thật sự đang lắng nghe trên VPS:

```bash
sudo ss -tulpn | grep -E ':(443|514|1514|1515|9200|55500)\b'
```

Kết quả đúng: `9200`, `443`, `55500`, `514` ở `127.0.0.1`; chỉ `1514`, `1515` ở `0.0.0.0`.

Chạy demo từ chính VPS (syslog chỉ nhận từ `127.0.0.1`):

```bash
python3 scripts/simulate_attack.py --host 127.0.0.1 --scenario full
docker exec -it attacker /opt/attack/full-attack.sh fs01
```

*(Chưa kiểm chứng)* Gói syslog gửi tới `127.0.0.1` đi qua docker-proxy, manager thấy nguồn là gateway bridge `172.x`, nằm trong `allowed-ips 172.16.0.0/12` của `ossec.conf`. Nếu không thấy alert thì kiểm tra điểm này trước.

### 9.7 Truy cập dashboard từ máy mình

```bash
ssh -N -L 8443:127.0.0.1:443 -L 9200:127.0.0.1:9200 user@<IP-VPS>
```

Mở `https://localhost:8443`. Tunnel `9200` cho phép chạy `scripts/eval_detection.py` từ laptop (`INDEXER_URL` mặc định `https://localhost:9200`), nhưng chạy thẳng trên VPS đơn giản hơn.

### 9.8 Phương án B: agent thật trỏ về VPS

Trước tiên mở `1514/tcp`, `1515/tcp` trên firewall nhà cung cấp, **chỉ** cho IP public của nơi đặt agent.

Windows (PowerShell quyền Administrator, từ gốc repo trên laptop):

```powershell
.\scripts\install-agent-windows.ps1 -Manager <IP-VPS> -AgentName laptop-win -RegistrationPassword '<noi-dung-authd.pass>'
```

Linux:

```bash
sudo bash scripts/install-agent-linux.sh -m <IP-VPS> -n vm-linux -P '<noi-dung-authd.pass>'
```

Xác nhận trên VPS: `docker exec siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l` thấy agent ở trạng thái `Active`.

Agent tự mở kết nối ra `1514/tcp` của manager, nên máy đặt sau NAT nhà mạng vẫn gửi được log mà không cần mở port nào phía endpoint. Đây là lý do mô hình SIEM tập trung trên cloud dùng được cho SMB có chi nhánh hoặc nhân viên làm từ xa.

Không gửi syslog của router nhà qua internet: UDP không mã hoá, IP nguồn giả mạo được, và `allowed-ips` hiện chỉ cho dải nội bộ.

### 9.9 Ba phép thử lấy bằng chứng cho chương 5

| Phép thử | Cách làm | Ghi lại |
|----------|----------|---------|
| Enroll không mật khẩu bị từ chối | Cài agent trên một máy **không** truyền `-P` / `-RegistrationPassword` | Dòng lỗi trong `ossec.log` của agent và trong log `wazuh.manager` |
| Mất kết nối rồi kết nối lại | Tắt mạng laptop 5 phút, tạo vài sự kiện (đăng nhập sai Windows), bật mạng lại | Thời điểm `agent_control -l` chuyển `Disconnected` → `Active`; sự kiện lúc mất mạng có về Indexer không *(agent có bộ đệm `<client_buffer>`, dung lượng mặc định cần tra tài liệu)* |
| FP theo ngày | `nohup python3 scripts/benign_traffic.py --profile both --duration 259200 > benign.log 2>&1 &` (3 ngày), sau đó `python3 scripts/eval_detection.py --fp-window '<bat dau>' '<ket thuc>'` | FP đo thật trong 3 ngày, không ngoại suy từ 1 giờ. **Không** chạy kịch bản tấn công trong khoảng này |

Đo năng lực trên cấu hình cố định của VPS:

```bash
bash scripts/measure_capacity.sh --endpoints 50 --retention 90
```

Ghi kèm cấu hình và giá thuê VPS vào báo cáo để có con số "N endpoint tốn X đồng/tháng".

### 9.10 Ngày bảo vệ

- Giữ bản local trên laptop chạy được (không có `COMPOSE_FILE` trong `.env`) để dự phòng mất mạng.
- Kiểm tra SSH tunnel và `agent_control -l` trước giờ bảo vệ 30 phút.
- Chỉ chạy `simulate_attack.py` và `attacker` nhắm vào máy của mình. Quét hoặc tấn công IP khác từ VPS có thể vi phạm điều khoản của nhà cung cấp.
