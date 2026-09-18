# Hai tầng rule: Wazuh rule và Correlation rule

> Giải thích sự khác nhau giữa `custom/rules/local_rules.xml` (rule Wazuh) và `correlation/rules/*.yml` (rule tương quan). Dùng cho chương thiết kế của báo cáo và cho người mới tiếp nhận hệ thống.

## 1. Vì sao phải có hai tầng

Một SIEM phải trả lời hai câu hỏi khác nhau:

1. **"Chuyện gì vừa xảy ra?"** — nhận diện một dòng log là sự kiện gì. Phải làm real-time, trên từng dòng log, khối lượng rất lớn.
2. **"Mấy chuyện đó có phải cùng một cuộc tấn công không?"** — ghép nhiều sự kiện rời rạc thành một kịch bản có nghĩa. Cần nhìn lại lịch sử, ghép nhiều nguồn log khác nhau.

Hai câu hỏi này có yêu cầu kỹ thuật đối nghịch: câu 1 cần nhanh và không trạng thái, câu 2 cần trạng thái dài hạn và truy vấn linh hoạt. Gộp vào một engine thì hoặc chậm, hoặc yếu. Vì vậy hệ thống tách thành hai tầng.

## 2. Bảng đối chiếu

| Tiêu chí | `custom/rules/local_rules.xml` | `correlation/rules/*.yml` |
|---|---|---|
| Engine | `wazuh-analysisd` (C, có sẵn của Wazuh) | `siem_correlator` (Python, tự viết) |
| Dữ liệu vào | **log thô** vừa tới, xử lý từng dòng | **alert đã sinh**, đọc lại từ Indexer |
| Thời điểm chạy | real-time, ngay khi log tới | định kỳ, quét cửa sổ thời gian đã qua |
| Lưu trạng thái | trong RAM, ngắn hạn (`timeframe` tính bằng giây) | truy vấn lại lịch sử, cửa sổ 15 phút – 2 giờ |
| Phạm vi nhìn thấy | một loại log, tại một thời điểm | mọi loại alert, nhiều nguồn, ghép được với nhau |
| Ngôn ngữ | XML, cú pháp Wazuh quy định | YAML, schema tự định nghĩa |
| Kết quả ra | alert vào `wazuh-alerts-*` | finding vào `siem-correlated-*` |
| Sửa rule | phải khởi động lại `analysisd` | correlator nạp lại từ thư mục rule |

## 3. Tầng 1 — Rule Wazuh: biến log thành alert

Nằm ở `custom/rules/local_rules.xml`, dải ID 100000–100999 dành cho rule tự viết. Làm đúng hai việc.

### 3.1 Gán ý nghĩa cho một dòng log

Không có trạng thái, không nhớ gì về quá khứ.

```xml
<rule id="100111" level="5">
  <if_sid>100100</if_sid>
  <status>FAILED</status>
  <description>erpapp: dang nhap that bai - user $(dstuser) tu $(srcip)</description>
  <group>authentication_failed,gdpr_IV_35.7.d,</group>
</rule>
```

Dòng log có `result=FAILED` thì sinh alert. Không quan tâm trước đó đã có bao nhiêu lần thất bại.

Các field `$(dstuser)`, `$(srcip)` do decoder `custom/decoders/local_decoder.xml` tách ra từ log thô. Rule chỉ so khớp trên field đã decode, không tự đọc log thô.

### 3.2 Đếm tần suất trong cửa sổ ngắn

```xml
<rule id="100120" level="10" frequency="6" timeframe="120">
  <if_matched_sid>100111</if_matched_sid>
  <same_source_ip />
  <same_user />
  <description>erpapp: nghi ngo brute force - $(srcip) that bai nhieu lan tren $(dstuser)</description>
</rule>
```

6 lần rule `100111` trong 120 giây, cùng IP nguồn, cùng tài khoản → brute force.

Đây đã là một dạng tương quan, nhưng bị giới hạn nặng:

- Chỉ nhận **một** `if_matched_sid` duy nhất — không ghép được nhiều loại sự kiện.
- Không ràng buộc được **thứ tự** nhiều chặng.
- Cửa sổ tính bằng giây, thực tế chỉ dùng được cỡ vài phút.
- Trạng thái nằm trong RAM của `analysisd`, khởi động lại là mất.

### 3.3 Giới hạn cứng

Không diễn đạt được mệnh đề dạng **"A rồi B rồi C"** khi A, B, C là ba loại sự kiện khác nhau. Đây chính là chỗ tầng 2 phải bù vào.

## 4. Tầng 2 — Rule tương quan (related): ghép alert thành kịch bản

Nằm ở `correlation/rules/*.yml`. Engine đọc `wazuh-alerts-*` trên Indexer, dịch rule YAML thành truy vấn OpenSearch. Ba kiểu rule, đúng những gì tầng 1 không làm được.

### 4.1 `sequence` — nhiều loại sự kiện, đúng thứ tự

```yaml
- id: account_takeover_to_exfil
  name: Chiem tai khoan roi xuat du lieu
  type: sequence
  severity: critical
  window: 3600
  join_field: data.dstuser
  stages:
    - name: bi_do_mat_khau
      filter:
        rule.id: ["100111"]
      min_count: 3
    - name: dang_nhap_thanh_cong
      filter:
        rule.id: ["100110"]
      min_count: 1
    - name: xuat_du_lieu
      filter:
        rule.id: ["100130", "100131"]
      min_count: 1
```

Ba loại alert khác nhau, cùng giá trị `data.dstuser`, xảy ra đúng thứ tự trong 1 giờ.

Wazuh không viết được rule này: `if_matched_sid` chỉ nhận một sid và không ràng buộc thứ tự nhiều chặng.

**`join_field` là điểm mấu chốt.** Nó là khoá nối các chặng lại. Nếu một trong các alert không có field đó thì chặng ấy không bao giờ ghép được — rule sẽ im lặng mà không báo lỗi. Ví dụ alert Windows để IP ở `data.win.eventdata.ipAddress` chứ không phải `data.srcip`, nên không thể trộn chung với alert SSH trong một rule join theo `data.srcip`.

### 4.2 `distinct` — đếm số giá trị khác nhau

```yaml
- id: impossible_travel
  type: distinct
  severity: high
  window: 900
  group_by: data.dstuser
  distinct_field: data.srcip
  min_cardinality: 3
  filter:
    rule.id: ["100110", "5715", "40112"]
```

Một tài khoản đăng nhập thành công từ ≥3 địa chỉ IP khác nhau trong 15 phút.

Wazuh có `<different_field>` nhưng chỉ khẳng định "khác nhau", **không đếm được có bao nhiêu giá trị phân biệt**.

### 4.3 `threshold` — đếm ngang qua nhiều rule

```yaml
- id: noisy_agent_high_severity
  type: threshold
  severity: medium
  window: 900
  group_by: agent.name
  min_count: 20
  filter:
    rule.level__gte: 10
```

20 alert **bất kỳ** có level ≥ 10 trên cùng một máy, trong 15 phút.

Wazuh đếm theo `if_matched_sid`, tức theo một rule cụ thể, không đếm ngang qua toàn bộ ruleset theo mức độ.

## 5. Luồng dữ liệu đầy đủ

```
log thô (syslog / agent)
  │
  ├─ decoder            custom/decoders/local_decoder.xml
  │                     tách field: status, dstuser, srcip, erp.*
  │
  ├─ rule Wazuh         custom/rules/local_rules.xml
  │                     100111 "dang nhap that bai"
  │
  ├─ wazuh-alerts-*     (Indexer)
  │
  ├─ correlator         correlation/rules/*.yml
  │                     đọc lại alert, ghép chuỗi theo join_field
  │
  ├─ siem-correlated-*  (Indexer)
  │
  ├─ bắn ngược vào manager qua socket /var/ossec/queue/sockets/queue
  │                     location "siem-correlator", payload JSON
  │
  ├─ rule 100900-100903 ánh xạ severity → level Wazuh
  │                     medium→10, high→12, critical→14
  │
  └─ wazuh-alerts-*     lên dashboard chung
```

Đoạn cuối quan trọng: finding tương quan **quay ngược lại thành alert Wazuh bình thường**. Nhờ vậy dashboard, cảnh báo email và active-response chỉ cần một đường ống duy nhất, không phải xử lý hai định dạng.

## 6. Hiệu quả lọc nhiễu

Vai trò của hai tầng nhìn từ khối lượng dữ liệu:

| Tầng | Nhiệm vụ | Khối lượng đo trên lab |
|---|---|---|
| Log thô | — | rất lớn, không thống kê trong repo |
| Tầng 1 (rule Wazuh) | nhận diện, lọc nhiễu | 2914 alert |
| Tầng 2 (correlation) | ghép ngữ cảnh | 54 finding |

Số liệu đo ngày 2026-09-07 trên các index `wazuh-alerts-4.x-*` và `siem-correlated-*` của lab. Phân bố finding theo rule:

| Rule tương quan | Số finding |
|---|---|
| `impossible_travel` | 36 |
| `brute_force_then_success` | 7 |
| `account_takeover_to_exfil` | 4 |
| `mass_data_export_by_user` | 4 |
| `noisy_agent_high_severity` | 2 |
| `scan_then_login_attempt` | 2 |
| `privilege_then_config_change` | 1 |

Cả 7 rule tương quan đều đã kích hoạt ít nhất một lần — không có rule viết ra rồi để chết.

## 7. Viết rule ở tầng nào?

Câu hỏi quyết định: **rule có cần nhìn quá một loại sự kiện, hoặc quá vài phút, hay không?**

Viết ở **tầng 1 (Wazuh)** khi:

- Nhận diện một loại log mới của ứng dụng.
- Điều kiện chỉ dựa trên nội dung của chính dòng log đó.
- Đếm lặp lại của **một** loại sự kiện, trong vài phút.
- Cần cảnh báo **tức thì**, không chấp nhận độ trễ.

Viết ở **tầng 2 (correlation)** khi:

- Kịch bản trải qua nhiều loại sự kiện khác nhau.
- Cần ràng buộc thứ tự các bước.
- Cửa sổ thời gian dài hơn vài phút.
- Cần đếm số giá trị phân biệt (`distinct`).
- Cần đếm ngang qua nhiều rule theo `rule.level` hoặc `rule.groups`.

Nguyên tắc chung: **đẩy càng nhiều việc lọc xuống tầng 1 càng tốt.** Tầng 2 truy vấn Indexer nên tốn tài nguyên hơn nhiều; nếu filter của rule tương quan quá rộng thì mỗi chu kỳ quét phải xử lý lượng dữ liệu lớn không cần thiết.

## 8. Bẫy thường gặp

### 8.1 Tầng 1

- **Rule cha bị rule con che.** `analysisd` dừng ở rule đầu tiên khớp. Rule `100120` và `100121` cùng nghe `100111`, nên `100120` phải có `<same_user />` để phân biệt rõ, nếu không `100121` (password spraying) không bao giờ nổ.
- **Rule level 0 không đếm được tần suất.** `analysisd` không lưu sự kiện của rule level 0 vào danh sách đối chiếu. Rule `100200` phải để level 2 (dưới ngưỡng ghi alert là 3, nên vẫn không gây nhiễu) để `100220` đếm được.
- **Static field và dynamic field.** Các tên `srcip`, `dstuser`, `srcuser`, `status`, `url`, `action`... là static field của Wazuh; trong rule phải gọi bằng thẻ riêng (`<status>`, `<srcip>`), không dùng được `<field name="...">` — nếu dùng sẽ lỗi `Field '...' is static`. Field nghiệp vụ riêng phải đặt tiền tố (ví dụ `erp.rows`) để thành dynamic field.

### 8.2 Tầng 2

- **`join_field` không tồn tại trong alert.** Rule chạy, không báo lỗi, nhưng không bao giờ sinh finding. Phải kiểm tra bằng truy vấn `exists` trên Indexer trước khi kết luận rule đã hoạt động.
- **Trộn nguồn log có sơ đồ field khác nhau.** Alert Linux và alert Windows đặt IP ở hai đường dẫn khác nhau — không join chung được, phải tách thành hai rule.
- **Rule cha có 0 alert là bình thường.** Khi rule con nổ thì alert mang ID của con. `100130` và `100140` luôn 0 alert vì `100131`, `100141` đã thay thế. Vẫn nên giữ cả cặp trong `filter` để bắt được trường hợp chỉ rule cha khớp.

## 9. Tài liệu liên quan

- `docs/adr/0001-kien-truc-tong-the.md` — quyết định kiến trúc tổng thể.
- `docs/so-tay-van-hanh.md` — quy trình vận hành hằng ngày, cách tinh chỉnh ngưỡng rule.
- `docs/bao-cao-outline.md` — đề cương báo cáo, chương thiết kế dẫn lại tài liệu này.
