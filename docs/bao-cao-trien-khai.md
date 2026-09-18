# Báo cáo triển khai hệ thống giám sát an ninh (SIEM) cho doanh nghiệp vừa và nhỏ

> Tài liệu này thuật lại toàn bộ quá trình triển khai thực tế của đồ án: từ chuẩn bị hạ tầng, dựng hệ thống, viết luật phát hiện, đến kiểm thử bằng các kịch bản tấn công giả lập. Mọi số liệu, đoạn cấu hình và tên luật đều lấy trực tiếp từ mã nguồn trong repo, không viết chay. Phần cuối nêu thẳng những hạn chế còn tồn tại để hội đồng đánh giá đúng phạm vi sản phẩm.

---

## 1. Mục tiêu và phạm vi triển khai

Đồ án đặt ra bài toán quen thuộc với doanh nghiệp vừa và nhỏ (SMB) tại Việt Nam: cần giám sát an ninh nhưng không đủ ngân sách mua SIEM thương mại, cũng không có đội chuyên trách an toàn thông tin. Người phụ trách công nghệ thông tin thường kiêm nhiệm nhiều việc, mỗi ngày chỉ dành được vài phút cho việc theo dõi cảnh báo.

Vì vậy, tiêu chí triển khai được đặt ra ngay từ đầu:

- **Chi phí phần mềm bằng không** — chỉ dùng phần mềm mã nguồn mở.
- **Một người vận hành được** — cài đặt bằng một câu lệnh, cảnh báo diễn giải bằng tiếng Việt dễ hiểu.
- **Chạy được trên phần cứng phổ thông** — một máy chủ tầm trung, không cần cụm nhiều máy.

Phạm vi giám sát gồm ba nhóm nguồn log: máy trạm (endpoint) chạy Windows/Linux, thiết bị mạng gửi log qua giao thức syslog, và một ứng dụng quản trị nội bộ (ký hiệu `erpapp`) mô phỏng hệ thống ERP của doanh nghiệp. Đồ án **không** bao gồm khả năng chịu lỗi nhiều node (High Availability) và cũng không tự động phản ứng đầy đủ như một nền tảng SOAR — đây là ranh giới đã xác định trước, không phải thiếu sót phát sinh.

---

## 2. Kiến trúc hệ thống

Hệ thống xây trên nền **Wazuh 4.x** chạy trong Docker một node, bổ sung thêm hai thành phần tự phát triển. Toàn bộ luồng dữ liệu như sau:

```
Nguồn log (agent, syslog, ứng dụng ERP)
        │
        ▼
  Wazuh Manager  ── decoder + ruleset (có phần tự viết)
        │  Filebeat
        ▼
  Wazuh Indexer  ◄──  Correlator (Python)
   wazuh-alerts-*      đọc alert, ghi lại
   siem-correlated-*   alert tương quan
        │
        ▼
  Wazuh Dashboard (https://localhost)
```

Điểm cốt lõi của thiết kế là **ba lớp phát hiện chồng lên nhau**, mỗi lớp bù đắp giới hạn của lớp dưới:

| Lớp | Vị trí | Phát hiện được gì | Giới hạn |
|-----|--------|-------------------|----------|
| Rule Wazuh có sẵn | Manager | Tấn công đã biết trên hệ điều hành và dịch vụ phổ biến | Không hiểu log của ứng dụng nội bộ riêng |
| Decoder + rule tự viết | `custom/` | Sự kiện của ứng dụng ERP: đăng nhập, xuất dữ liệu, cấp quyền, sửa giá | Cửa sổ thời gian ngắn, chỉ nhìn một nguồn log |
| Engine tương quan | `correlation/` | Chuỗi hành vi trải qua nhiều nguồn log, cửa sổ tới vài giờ | Chạy theo chu kỳ (mặc định 60 giây), chưa phải thời gian thực |

Cách hình dung đơn giản: lớp một là **bộ cảm biến có sẵn của nhà sản xuất**, lớp hai là **cảm biến tự lắp cho đúng thiết bị của mình**, lớp ba là **người bảo vệ ghép các sự kiện rời rạc lại thành một câu chuyện tấn công**. Một luật đơn lẻ chỉ thấy "có người gõ sai mật khẩu" hoặc "có người xuất dữ liệu"; chỉ khi ghép chuỗi lại mới nhận ra "tài khoản bị dò mật khẩu, rồi đăng nhập được, rồi mang dữ liệu đi".

---

## 3. Chuẩn bị hạ tầng

Yêu cầu tối thiểu để chạy được toàn bộ stack:

- Docker Engine kèm Docker Compose phiên bản 2.
- RAM cấp cho Docker từ 6 GB trở lên (riêng Wazuh Indexer đã dùng 1 GB heap mặc định).
- Ổ đĩa trống từ 20 GB.
- Tham số nhân `vm.max_map_count` phải đạt tối thiểu 262144 — đây là điều kiện bắt buộc của công cụ tìm kiếm nền dưới (OpenSearch); thiếu tham số này thì Indexer khởi động lên rồi tắt ngay.

Trên máy Linux:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Trên Docker Desktop dùng WSL2 (Windows):

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

Đây là bước hay bị bỏ sót nhất khi triển khai lần đầu, và triệu chứng của nó — container Indexer cứ lặp lại chu kỳ khởi động rồi tắt — dễ bị nhầm là lỗi cấu hình phức tạp, trong khi thực chất chỉ là một tham số nhân.

---

## 4. Các bước triển khai

### 4.1 Dựng stack tự động

Cách được khuyến nghị là chạy đúng một câu lệnh:

```bash
bash scripts/deploy.sh
```

Script này làm tuần tự: sinh chứng chỉ TLS, khởi động các container, và **quan trọng nhất** là khởi tạo chỉ mục bảo mật của Indexer.

### 4.2 Dựng stack thủ công (khi cần hiểu từng bước)

```bash
cd docker/single-node
docker compose -f generate-certs.yml run --rm generator
docker compose up -d
```

Khi làm thủ công, **bắt buộc** chạy thêm bước khởi tạo bảo mật cho Indexer. Bỏ bước này thì mọi yêu cầu đều trả về `OpenSearch Security not initialized` (mã lỗi HTTP 503) và không đăng nhập được vào dashboard:

```bash
docker exec siem-raw-wazuh.indexer-1 bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -icl -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost -p 9200'
```

Sau khi các dịch vụ lên, truy cập `https://localhost` với tài khoản `admin` / `SecretPassword`.

> **Cảnh báo bảo mật:** mật khẩu và chứng chỉ trong repo chỉ là giá trị demo. Phải đổi trước khi dùng thật. Mật khẩu nằm trong `docker/single-node/.env`, hash bcrypt tương ứng nằm trong `config/wazuh_indexer/internal_users.yml`.

### 4.3 Cài agent lên máy trạm

Agent là chương trình nhỏ chạy trên từng máy cần giám sát, thu log tại chỗ và gửi về máy chủ Wazuh. Trước khi cài, cần biết ba cổng mà máy chủ mở ra (khai báo trong `config/wazuh_manager/ossec.conf`):

| Cổng | Giao thức | Dùng cho |
|------|-----------|----------|
| 1514 | TCP | Kênh truyền log đã mã hóa từ agent về manager |
| 1515 | TCP | Đăng ký agent lần đầu (enrollment) — đồ án đặt `use_password=no` nên agent tự đăng ký, không cần khóa |
| 514 | UDP | Nhận syslog từ thiết bị không cài được agent |

Trong tất cả lệnh dưới đây, thay `<IP-manager>` bằng địa chỉ IP thật của máy chủ Wazuh trong mạng nội bộ (ví dụ `192.168.1.10`).

#### 4.3.1 Máy Linux (Ubuntu/Debian — dùng gói `.deb`)

Gói `wazuh-agent_4.9.2-1_amd64.deb` đã có sẵn ở gốc repo; nếu máy đích có Internet có thể tải trực tiếp từ kho Wazuh. Ba biến môi trường `WAZUH_MANAGER`, `WAZUH_AGENT_NAME`, `WAZUH_AGENT_GROUP` được phần cài đặt của gói đọc và ghi thẳng vào `ossec.conf`, nên không phải sửa file cấu hình bằng tay:

```bash
# Tải gói (bỏ qua nếu đã copy sẵn file .deb sang máy)
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb

# Cài kèm khai báo địa chỉ manager, tên máy, nhóm agent
sudo WAZUH_MANAGER='<IP-manager>' WAZUH_AGENT_NAME='pc01' WAZUH_AGENT_GROUP='default' \
  dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb

# Bật dịch vụ và cho tự khởi động cùng máy
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

Với dòng máy RHEL/CentOS/Rocky dùng gói `.rpm` thay cho `.deb`, cài bằng `rpm -ihv` với đúng ba biến môi trường trên.

Kiểm tra agent đã kết nối:

```bash
sudo /var/ossec/bin/wazuh-control status
sudo grep "Connected to the server" /var/ossec/logs/ossec.log
```

#### 4.3.2 Máy Windows (gói MSI)

Cài bằng dòng lệnh để nhúng sẵn địa chỉ manager (chạy PowerShell **quyền Administrator**):

```powershell
# Tải gói cài đặt
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile $env:TEMP\wazuh-agent.msi

# Cài im lặng kèm khai báo manager và tên máy
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER="<IP-manager>" WAZUH_AGENT_NAME="pc-ketoan" WAZUH_AGENT_GROUP="default"

# Khởi động dịch vụ
NET START WazuhSvc
```

Kiểm tra trạng thái:

```powershell
& "C:\Program Files (x86)\ossec-agent\bin\wazuh-control.exe" status
```

Có thể thay việc tải gói bằng cách chạy trình cài đặt đồ họa của MSI; khi đó nhập địa chỉ manager vào ô **Manager IP** ở màn hình cấu hình rồi bấm Install.

#### 4.3.3 Xác nhận trên máy chủ

Bất kể agent là Windows hay Linux, sau khi cài xong kiểm tra ở phía manager — trạng thái phải là **Active**:

```bash
docker exec siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Hoặc mở dashboard vào mục **Agents management** để thấy danh sách agent đang kết nối.

#### 4.3.4 Riêng máy chủ ứng dụng ERP — khai báo đọc log ứng dụng

Agent mặc định chỉ đọc log hệ thống, chưa biết file log riêng của ứng dụng ERP. Trên máy chạy ERP, thêm khối khai báo trong `docker/agents/config/erp01-localfile.xml` vào trước thẻ `</ossec_config>` cuối cùng của file `ossec.conf` phía agent, rồi khởi động lại agent. Khối này trỏ agent tới `/var/log/erpapp/app.log` — đúng định dạng mà decoder tự viết bóc tách được.

#### 4.3.5 Thiết bị không cài được agent

Router, switch, firewall, NAS không cài agent được thì bật tính năng gửi syslog của thiết bị, trỏ về `<IP-manager>` cổng `514/udp`. Dải IP được phép gửi syslog phải khai báo trong `ossec.conf` và thu hẹp đúng theo mạng nội bộ của doanh nghiệp, tránh nhận log giả mạo từ bên ngoài.

> **Ghi chú môi trường lab:** đồ án còn kèm ba container Ubuntu (`erp01`, `fs01`, `pc01` trong `docker/agents/`) đóng vai máy trạm/máy chủ để thực hành đúng quy trình onboarding mà không cần máy vật lý. Trong lab, `<IP-manager>` thay bằng hostname `wazuh.manager` vì các container dùng chung mạng Docker. Quy trình cài bên trong container giống hệt mục 4.3.1, chỉ khác gói `.deb` được mount sẵn tại `/opt/wazuh-agent.deb` nên không cần Internet.

### 4.4 Nạp và kiểm thử decoder, rule tự viết

Sau khi sửa file trong thư mục `custom/`, nạp lại ruleset bằng cách khởi động lại manager:

```bash
docker compose -f docker/single-node/docker-compose.yml restart wazuh.manager
```

Điểm mấu chốt khi viết rule là: **một rule sai hầu như không báo lỗi**. Nó chỉ im lặng (không bao giờ khớp) hoặc khớp nhầm sang loại sự kiện khác. Vì vậy không thể tin rule đúng chỉ vì manager nạp được — phải kiểm chứng bằng cách cho một dòng log đã biết trước kết quả rồi xem hệ thống thực sự sinh ra alert nào. Đó là vai trò của `scripts/test_rules.sh`:

```bash
bash scripts/test_rules.sh
```

**Công cụ script dùng để test là `wazuh-logtest`** — một chương trình có sẵn của Wazuh, chính là phiên bản tương tác của bộ máy phân tích thật (`wazuh-analysisd`). Nó nạp đúng bộ decoder và ruleset đang chạy, nhận một dòng log qua đầu vào chuẩn, chạy dòng đó qua toàn bộ quy trình xử lý rồi in ra kết quả từng bước. Script bơm lần lượt các dòng log mẫu vào công cụ này bên trong container manager và lọc lấy phần kết quả để đối chiếu:

```bash
printf '<dòng log>' | docker exec -i siem-raw-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Cần nhấn mạnh: `wazuh-logtest` chạy độc lập, **không cần agent và không cần Indexer**. Nó test thẳng vào lõi phân tích của manager, nên phản hồi tức thì và thích hợp cho vòng lặp sửa–thử khi phát triển rule.

Một dòng log đi qua ba giai đoạn (phase), và đây cũng là lý do phải "đối chiếu log":

1. **Pre-decoding** — tách các trường cơ bản của dòng syslog: thời gian, tên máy, tên chương trình.
2. **Decoding** — đây chính là **bước bóc trường (field)** mà câu hỏi nêu. Decoder `erpapp-*` tự viết bóc các trường nghiệp vụ ra khỏi phần nội dung log: `result`, `user`, `srcip`, `rows`, `module`... Không có bước này thì log chỉ là một chuỗi văn bản thô.
3. **Rule matching** — rule đọc *các trường vừa bóc được ở bước 2* và so khớp điều kiện; khớp thì sinh alert kèm ID và mức độ.

Ba giai đoạn phụ thuộc nhau theo dây chuyền: nếu decoder ở bước 2 không bóc được trường, rule ở bước 3 không có gì để so và sẽ im lặng. Vì vậy script lọc kết quả bằng cả từ khóa của bước bóc trường (`decoder`, `dstuser`, `srcip`) lẫn từ khóa của bước so rule (`id:`, `level:`) — để nhìn được đứt gãy nằm ở giai đoạn nào.

Quan trọng hơn, `test_rules.sh` được viết như một bộ **kiểm thử hồi quy**: bên cạnh các log hợp lệ, nó cố tình nhét lại những dòng log từng làm lộ bốn lỗi đã vá (nêu ở mục 7), mỗi dòng ghi sẵn kết quả kỳ vọng ngay bên cạnh để đối chiếu bằng mắt khi chạy:

| Dòng log thử | Kỳ vọng | Chứng minh điều gì |
|--------------|---------|--------------------|
| `result=NOTOK` | ra `100101`, **không** ra `100110` | Điều kiện đăng nhập thành công vẫn neo `^OK$`, không khớp chuỗi con |
| `rows=00012` | ra `100130`, **không** ra `100131` | Ngưỡng 10000 so bằng *giá trị số*, không đếm *số chữ số* |
| `rows=10000` | ra `100131` | Biểu thức `pcre2` còn hiệu lực (nếu ra `100130` tức là mất `type="pcre2"`) |
| Thiếu field `file=`, đổi thứ tự field, giá trị có khoảng trắng | ra `100101` | Log hỏng rơi đúng vào rule báo "decoder mù", không biến mất |

Nhờ vậy, mỗi lần sửa file trong `custom/`, chạy lại script là biết ngay thay đổi mới có vô tình làm hỏng luật đang chạy đúng hay không — thay vì chờ đến lúc demo trước hội đồng mới phát hiện.

### 4.5 Chạy engine tương quan và dashboard

Engine tương quan chạy như một container riêng, đọc alert từ Indexer theo chu kỳ và ghi alert tương quan trở lại chỉ mục `siem-correlated-*`. Có thể chạy thử ngoài container để in kết quả ra màn hình mà không ghi gì:

```bash
cd correlation
INDEXER_URL=https://localhost:9200 INDEXER_PASSWORD=SecretPassword python -m siem_correlator --once --dry-run
```

Dashboard được sinh và nhập vào hệ thống:

```bash
python dashboards/build_dashboard.py
# Sau đó: Dashboards Management → Saved objects → Import file .ndjson
```

---

## 5. Lớp phát hiện tự viết

### 5.1 Decoder và rule cho ứng dụng nội bộ

Ứng dụng ERP giả lập sinh log mà Wazuh mặc định không hiểu. Đồ án viết decoder trong `custom/decoders/local_decoder.xml` để bóc tách các loại sự kiện: đăng nhập, xuất dữ liệu, cấp quyền, sửa giá đơn hàng. Trên nền đó, `custom/rules/local_rules.xml` định nghĩa các luật phát hiện, dùng dải ID từ 100100 trở lên (dải dành riêng cho luật tự viết, tránh đè lên luật gốc của Wazuh).

Một số luật tiêu biểu:

| ID | Mức | Phát hiện |
|----|-----|-----------|
| 100120 | 10 | Dò mật khẩu (brute force): 6 lần thất bại trong 120 giây từ cùng một IP |
| 100121 | 10 | Rải mật khẩu (password spraying): một IP thử nhiều tài khoản khác nhau |
| 100122 | 6 | Đăng nhập ngoài giờ hành chính |
| 100130 / 100131 | 5 / 10 | Xuất dữ liệu nhạy cảm / xuất hàng loạt từ 10000 dòng trở lên |
| 100140 / 100141 | 8 / 12 | Cấp quyền / cấp quyền **quản trị** |
| 100150 | 7 | Sửa giá đơn hàng (dấu hiệu gian lận nghiệp vụ) |
| 100220 | 10 | Quét cổng: 15 lần bị firewall chặn trong 60 giây |
| 100901–100903 | 10–14 | Alert do engine tương quan sinh ra, đi ngược qua ruleset |

### 5.2 Engine tương quan

Engine viết bằng Python trong `correlation/siem_correlator/`, luật khai báo bằng YAML để người vận hành sửa được mà không cần đụng vào mã. Ba kiểu luật:

- **`threshold`** — đếm số alert theo một khóa nhóm trong cửa sổ thời gian. Ví dụ: một tài khoản xuất dữ liệu từ 5 lần trở lên trong 30 phút.
- **`distinct`** — đếm số giá trị *khác nhau* của một trường. Ví dụ: một tài khoản đăng nhập thành công từ 3 địa chỉ IP trở lên trong 15 phút (dấu hiệu tài khoản dùng chung hoặc lộ mật khẩu).
- **`sequence`** — nhiều giai đoạn phải xảy ra *đúng thứ tự* trên cùng một khóa ghép. Đây là kiểu mạnh nhất, phát hiện được chuỗi tấn công mà không luật đơn lẻ nào bắt được.

Ví dụ luật chuỗi phát hiện chiếm tài khoản rồi lấy dữ liệu (trích từ `correlation/rules/smb_attack_chain.yml`):

```yaml
- id: account_takeover_to_exfil
  name: Chiem tai khoan roi xuat du lieu
  type: sequence
  severity: critical
  window: 3600            # 1 giờ
  join_field: data.dstuser
  mitre: [T1110, T1078, T1567]
  stages:
    - name: bi_do_mat_khau       # Giai đoạn 1: bị dò mật khẩu
      filter: { rule.id: ["100111"] }
      min_count: 3
    - name: dang_nhap_thanh_cong # Giai đoạn 2: đăng nhập được
      filter: { rule.id: ["100110"] }
    - name: xuat_du_lieu         # Giai đoạn 3: xuất dữ liệu
      filter: { rule.id: ["100130", "100131"] }
```

Một chi tiết thiết kế đáng chú ý: mỗi alert tương quan được gán một định danh `_id` **tất định** (tính từ nội dung, không phải ngẫu nhiên). Nhờ vậy, chạy lại engine trên cùng một cửa sổ thời gian sẽ *ghi đè* alert cũ chứ không nhân bản — tránh tình trạng một sự cố bị đếm thành hàng chục cảnh báo trùng lặp.

Đồ án định nghĩa bảy luật tương quan, mỗi luật ánh xạ tới một hoặc nhiều kỹ thuật trong khung MITRE ATT&CK: `brute_force_then_success`, `account_takeover_to_exfil`, `impossible_travel`, `scan_then_login_attempt`, `privilege_then_config_change`, `noisy_agent_high_severity`, `mass_data_export_by_user`.

---

## 6. Kịch bản tấn công và kiểm thử

Để chứng minh hệ thống thật sự phát hiện được tấn công (chứ không chỉ chạy lên là xong), đồ án viết công cụ giả lập `scripts/simulate_attack.py`. Công cụ sinh ra các sự kiện y như tấn công thật, bơm vào hệ thống, rồi đối chiếu alert nào đã nổ.

```bash
python scripts/simulate_attack.py --scenario full
```

Chín kịch bản, phủ từ tấn công đơn giản đến chuỗi phức tạp:

| Kịch bản | Mô phỏng | Alert kỳ vọng |
|----------|----------|---------------|
| `bruteforce` | 8 lần sai mật khẩu cùng một tài khoản | 100111, 100120 |
| `spray` | Một IP thử lần lượt 10 tài khoản | 100111, 100121 |
| `exfil` | Xuất dữ liệu hàng loạt | 100130, 100131, `mass_data_export_by_user` |
| `portscan` | 20 lần bị firewall chặn trong vài giây | 100200, 100220 |
| `scan-then-login` | Quét cổng rồi chuyển sang dò mật khẩu | 100220 + `scan_then_login_attempt` |
| `impossible-travel` | Một tài khoản đăng nhập thành công từ 4 IP | 100110 + `impossible_travel` |
| `insider` | Nhân viên đăng nhập hợp lệ rồi lấy dữ liệu, sửa giá | 100131, 100150 + `mass_data_export_by_user` |
| `full` | Dò mật khẩu → vào được → tự cấp quyền admin → xuất dữ liệu → sửa giá | 100120, 100141, 100131, 100150 + `brute_force_then_success`, `account_takeover_to_exfil` |
| `all` | Chạy lần lượt tất cả (70 sự kiện) | toàn bộ |

Giá trị lớn nhất nằm ở kịch bản `full`: nó tái hiện một cuộc tấn công hoàn chỉnh. Từng bước riêng lẻ đều sinh alert ở lớp Wazuh, nhưng **chỉ lớp tương quan mới ghép được toàn bộ thành một câu chuyện** và báo `account_takeover_to_exfil` mức nghiêm trọng. Đây chính là điểm khác biệt mà đồ án muốn chứng minh: giá trị của việc bổ sung lớp tương quan so với chỉ dùng luật đơn lẻ.

**Lưu ý kỹ thuật khi demo:** tham số `--delay` phải để nhỏ hơn hoặc bằng 1.0 giây. Lý do là các luật tần suất của Wazuh có cửa sổ thời gian cố định (dò mật khẩu 6 lần/120 giây, quét cổng 15 lần/60 giây); nếu để delay lớn thì sự kiện tràn ra ngoài cửa sổ và luật không kích hoạt — người demo sẽ tưởng hệ thống hỏng trong khi thực chất là canh giờ sai.

Kiểm chứng kết quả sau khi chạy:

1. Vào **Wazuh Dashboard → Threat Hunting**: thấy các alert lớp một và lớp hai (100111, 100120, 100131, 100141).
2. Vào dashboard **"SIEM-raw - Alert tương quan"**: thấy các alert lớp ba (`brute_force_then_success`, `account_takeover_to_exfil`).
3. Xem log engine: `docker compose -f docker/single-node/docker-compose.yml logs -f correlator`.

Ngoài kiểm thử end-to-end, engine tương quan còn có unit test chạy độc lập không cần Indexer:

```bash
python correlation/tests/test_engine.py
```

---

## 7. Những vấn đề đã vấp phải và cách khắc phục

Phần này ghi lại các lỗi thực tế gặp trong quá trình triển khai. Chúng đều đã được vá trong repo, nhưng ghi lại đây vì mỗi lỗi là một bài học về cách hệ thống hoạt động bên dưới — và vì hội đồng thường hỏi "gặp khó khăn gì".

**Nhóm lỗi khi dựng hệ thống:**

1. **`OpenSearch Security not initialized` (HTTP 503).** Lần chạy đầu, plugin bảo mật chưa tạo chỉ mục nên mọi yêu cầu đều bị từ chối. Phải nạp cấu hình bảo mật một lần bằng công cụ `securityadmin.sh`. Đáng lưu ý: script `indexer-security-init.sh` có sẵn trong image *không dùng được* với bản Docker vì nó tìm đường dẫn của bản cài bằng gói RPM/DEB.

2. **Manager chết khi khởi động: `Could not open file 'etc/shared/ar.conf'`.** Nguyên nhân là bind-mount file cấu hình tùy chỉnh *vào bên trong* một named volume, khiến Docker coi volume là "đã có dữ liệu" và không sao chép nội dung gốc từ image. Cách đúng là mount qua `/wazuh-config-mount` để script khởi tạo của image tự sao chép vào đúng chỗ.

**Nhóm lỗi khi viết decoder/rule** (mỗi lỗi tương ứng một đặc tính của bộ máy phân tích Wazuh):

3. **Decoder con phải có `<prematch>`.** Bốn decoder cùng chung một cha; thiếu `<prematch>` thì chỉ decoder đầu tiên hoạt động, các loại sự kiện xuất dữ liệu / cấp quyền / sửa giá không bóc được trường nào nên luật tương ứng không bao giờ nổ.

4. **So khớp không neo `^...$` là so khớp chuỗi con.** Điều kiện `<status>OK</status>` vô tình khớp cả `NOTOK`, `TOKEN_EXPIRED`, `BLOCKED`. Hậu quả nghiêm trọng: luật tương quan kết luận *ngược* — một cuộc tấn công đã bị khóa tài khoản lại bị báo là đã chiếm được tài khoản. Đã sửa thành `^OK$` / `^FAILED$`.

5. **`<time>` so theo giờ UTC, không theo múi giờ container.** Luật phát hiện đăng nhập ngoài giờ ban đầu bắt nhầm khung 09:00–12:00 giờ Việt Nam và sinh **469 cảnh báo sai**. Phải tự trừ 7 tiếng khi khai báo khung giờ.

6. **Trường static và dynamic.** Wazuh chia trường log thành hai loại với cú pháp gọi khác nhau; gọi sai cho lỗi `Field '...' is static` và manager không nạp được ruleset. Các trường nghiệp vụ riêng của ứng dụng đều phải đặt tiền tố `erp.` để trở thành trường động.

Bài học chung rút ra: phần khó nhất của một SIEM không phải là dựng hệ thống lên, mà là **làm cho luật phát hiện chính xác** — sai một chi tiết nhỏ trong biểu thức khớp có thể khiến luật im lặng hoàn toàn hoặc, tệ hơn, báo ngược sự thật.

---

## 8. Hạn chế của hệ thống

Trình bày thẳng thắn để hội đồng đánh giá đúng phạm vi. Đây là những giới hạn *có ý thức*, đi kèm lý do và hướng khắc phục.

| Hạn chế | Ảnh hưởng | Hướng phát triển |
|---------|-----------|------------------|
| **Một node, không chịu lỗi (không HA)** | Máy chủ hỏng thì mất giám sát cho tới khi khôi phục | Mở rộng thành cụm nhiều node Indexer + Manager |
| **Tương quan chạy theo chu kỳ (60 giây), chưa thời gian thực** | Alert tương quan trễ tối đa một chu kỳ so với sự kiện | Chuyển sang xử lý dòng (streaming) hoặc rút ngắn chu kỳ |
| **Chưa tích hợp threat intelligence** | Không tự nhận diện IP/mã băm độc đã biết từ nguồn ngoài | Làm giàu dữ liệu bằng nguồn threat intel công khai |
| **Chưa có phản ứng tự động đầy đủ (SOAR)** | Phát hiện được nhưng việc chặn/cô lập vẫn làm thủ công | Tích hợp active response, kịch bản phản ứng tự động |
| **Cổng 9200 và 55000 mở ra host** | Tiện phát triển nhưng là bề mặt tấn công nếu để nguyên khi lên thật | Khi triển khai thật chỉ bind `127.0.0.1` |
| **Mật khẩu/chứng chỉ demo trong repo** | Không an toàn nếu dùng nguyên trạng | Đổi toàn bộ trước khi vận hành thật |
| **Ứng dụng ERP là mô phỏng** | Log do script sinh, chưa phải hệ thống nghiệp vụ thật | Tích hợp với ứng dụng thật của doanh nghiệp khi áp dụng |

Điểm cần nhấn mạnh: hai hạn chế đầu (không HA và tương quan theo chu kỳ) là **đánh đổi có chủ đích** để đạt mục tiêu "một người vận hành trên phần cứng phổ thông". Với quy mô SMB — vài chục đến vài trăm endpoint — độ trễ một phút của lớp tương quan là chấp nhận được, và chi phí dựng cụm HA thường vượt quá giá trị nó mang lại. Đây là quyết định phù hợp bối cảnh, không phải giới hạn kỹ thuật không vượt qua được.

---

## 9. Kết luận

Đồ án đã dựng được một hệ thống SIEM chạy thật, đạt cả ba tiêu chí đặt ra ban đầu: chi phí phần mềm bằng không, cài đặt bằng một câu lệnh, và một người vận hành được với sổ tay hướng dẫn bằng tiếng Việt. Đóng góp riêng — vượt trên việc chỉ cấu hình một sản phẩm có sẵn — nằm ở hai lớp tự phát triển: bộ decoder/rule cho ứng dụng nội bộ, và engine tương quan phát hiện chuỗi tấn công qua nhiều nguồn log. Các kịch bản kiểm thử giả lập đã chứng minh giá trị thực của lớp tương quan: những chuỗi tấn công mà từng luật đơn lẻ bỏ sót đều được ghép lại và cảnh báo đúng mức nghiêm trọng.

Hệ thống chưa phải là một nền tảng phòng thủ hoàn chỉnh cấp doanh nghiệp lớn — và cũng không đặt mục tiêu đó. Nó là một giải pháp *vừa đủ và đúng đối tượng* cho doanh nghiệp vừa và nhỏ, phần còn thiếu đã được nêu rõ kèm hướng đi tiếp theo.

---

## Phụ lục — tài liệu liên quan trong repo

- `README.md` — hướng dẫn cài đặt và vận hành đầy đủ.
- `docs/so-tay-van-hanh.md` — sổ tay cho người phụ trách CNTT: việc hằng ngày, quy trình xử lý sự cố, xử lý lỗi hệ thống.
- `docs/bao-cao-outline.md` — đề cương báo cáo tốt nghiệp đầy đủ sáu chương.
- `custom/` — decoder và rule tự viết.
- `correlation/` — mã nguồn engine tương quan, rule YAML, unit test.
- `scripts/simulate_attack.py` — công cụ giả lập tấn công dùng khi demo và kiểm thử.
