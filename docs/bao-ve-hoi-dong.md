# Chuẩn bị bảo vệ — trả lời hội đồng

Tài liệu này trả lời từng câu hỏi phản biện dự kiến, bám đúng mã nguồn trong repo.

Quy ước nhãn:

- **[Đã kiểm chứng trong repo]** — đọc được trực tiếp từ code/config.
- **[Suy luận]** — kết luận logic rút ra từ code, chưa chạy thực nghiệm để xác nhận.
- **[Chưa kiểm chứng]** — cần đo/chạy thử mới khẳng định được; có kèm lệnh kiểm tra.

---

## PHẦN I — Lõi kỹ thuật (engine tương quan)

### Câu 1 — Điều kiện thứ tự `first[i] <= last[i+1]`

**Trước hết, xin đính chính chính ví dụ mà thầy đưa ra.** Với dữ liệu
`stage3 = {08:00}`, `stage1 = {08:30}`, `stage2 = {08:40}` — rule **không** nổ.
Kiểm tra cặp thứ hai: `stage2.first = 08:40 <= stage3.last = 08:00` → sai → `ordered = False`.
[Đã kiểm chứng trong repo — `correlation/siem_correlator/engine.py`, hàm `_run_sequence`]

**Nhưng điều kiện này thật sự lỏng, và em có ví dụ dương tính giả chứng minh.**

Rule `account_takeover_to_exfil`, join theo `data.dstuser`, cửa sổ 1 giờ (09:00–09:59).
Một kế toán viên trong một buổi sáng bình thường:

| Thời điểm | Sự kiện | Rơi vào giai đoạn |
|---|---|---|
| 09:05 | Đăng nhập đầu ngày (100110) | stage2 |
| 09:10 | Xuất báo cáo công nợ (100130) | stage3 |
| 09:20 | Xuất báo cáo bán hàng (100130) | stage3 |
| 09:30–09:32 | Hết phiên, gõ sai mật khẩu 3 lần (100111 ×3) | stage1 |
| 09:50 | Đăng nhập lại thành công (100110) | stage2 |

Giá trị agg: `stage1.first=09:30`; `stage2.first=09:05, last=09:50`; `stage3.first=09:10, last=09:20`.

- `stage1.first (09:30) <= stage2.last (09:50)` → đúng
- `stage2.first (09:05) <= stage3.last (09:20)` → đúng

→ **Rule nổ, severity `critical`, "tài khoản bị chiếm rồi xuất dữ liệu".** Thực tế không có
lần xuất dữ liệu nào **sau** khi đăng nhập lại. Đây là dương tính giả thật, kịch bản hoàn toàn
đời thường. [Suy luận — đối chiếu trực tiếp với code, chưa chạy thực nghiệm]

**Nguyên nhân gốc:** điều kiện kiểm tra theo **từng cặp liền kề**, và mỗi cặp lại lấy `first`
của giai đoạn trước so với `last` của giai đoạn sau — tức lấy mốc **sớm nhất** so với mốc
**muộn nhất**, giá trị dễ thoả nhất ở cả hai bên. Chuỗi ba giai đoạn không bị ràng buộc phải
nhất quán trên **cùng một** dòng thời gian.

**Tại sao không viết `last[i] <= first[i+1]`?** Vì như vậy quá chặt và sẽ giết chính kịch bản
đúng: brute force thường **vẫn tiếp diễn** sau khi kẻ tấn công đã vào được (các bot khác vẫn
dò), nên `last(do_mat_khau)` thường lớn hơn `first(dang_nhap_thanh_cong)`. Rule sẽ không bao
giờ nổ.

**Em nhận đây là điểm yếu và có phương án sửa — xem Câu 2.**

### Câu 2 — Đánh đổi có chủ đích hay giới hạn kỹ thuật?

Là **đánh đổi có chủ đích, nhưng em đã chọn sai điểm dừng**.

Chủ đích: mỗi giai đoạn chỉ tốn **một** truy vấn `terms` agg cho **toàn bộ** các khoá, thay vì
`N_khoá × N_giai_đoạn` truy vấn. Với 3 giai đoạn, chi phí là 3 request, `size: 0` (không kéo
document), độ phức tạp không phụ thuộc số khoá. Đó là lý do engine chạy được trên máy 6 GB RAM
cùng chỗ với Indexer.

Cái giá: `min`/`max` chỉ cho biết **khoảng** của mỗi giai đoạn, mất hoàn toàn thứ tự từng sự kiện.

**Phương án đúng — hai tầng, chi phí gần như không đổi:**

Tầng 1 giữ nguyên (agg, lọc thô, cắt từ hàng nghìn khoá xuống vài khoá ứng viên).
Tầng 2 chỉ chạy trên các khoá còn sót, xác minh thứ tự bằng sự kiện thật với con trỏ thời gian
tiến dần:

```python
def _verify_sequence(self, rule, key, start, end):
    """Xac minh thu tu THAT tren mot khoa ung vien.

    Con tro `cursor` chi tien: giai doan sau bat buoc phai co du min_count
    su kien XAY RA SAU su kien cuoi cung cua giai doan truoc.
    Tra ve None neu chuoi khong hop le.
    """
    cursor = start
    timeline = []
    for stage in rule.stages:
        body = {
            "size": stage.min_count,
            "sort": [{"@timestamp": "asc"}],
            "_source": ["@timestamp", "rule.id", "rule.description", "agent.name"],
            "query": {
                "bool": {
                    "filter": build_filter(stage.filter)
                    + [
                        {"term": {rule.join_field: key}},
                        {"range": {"@timestamp": {"gte": cursor.isoformat(),
                                                  "lt": end.isoformat()}}},
                    ]
                }
            },
        }
        hits = self.client.search(self.alerts_index, body)["hits"]["hits"]
        if len(hits) < stage.min_count:
            return None                      # khong du su kien SAU moc truoc -> loai
        last_ts = hits[-1]["_source"]["@timestamp"]
        cursor = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
        timeline.append({"name": stage.name, "hits": hits})
    return timeline
```

Chi phí thêm: `số_khoá_ứng_viên × số_giai_đoạn` truy vấn `size <= min_count`. Trong toàn bộ 9
kịch bản demo, số khoá ứng viên là 1–2, tức thêm 3–6 request nhẹ mỗi chu kỳ 60 giây.

Lợi thêm: `evidence` chuyển từ "khoảng thời gian của giai đoạn" thành **danh sách sự kiện thật**,
analyst mở alert ra là thấy đúng dòng log — giá trị điều tra cao hơn hẳn.

**Áp dụng vào ví dụ Câu 1:** con trỏ sau stage1 là 09:32; truy vấn stage2 từ 09:32 → tìm thấy
09:50, con trỏ = 09:50; truy vấn stage3 từ 09:50 → **không có sự kiện nào** → trả `None` →
dương tính giả bị loại. [Suy luận]

### Câu 3 — `impossible_travel` không có địa lý

Thầy nói đúng, và em nhận **tên rule đang mô tả sai logic**.

Cái em cài đặt là: một tài khoản đăng nhập thành công từ ≥ 3 địa chỉ IP khác nhau trong 15 phút
— đây là **"đăng nhập đồng thời từ nhiều nguồn"** (concurrent multi-source login), không phải
impossible travel. Impossible travel đòi hỏi toạ độ địa lý và phép tính vận tốc:
`khoảng_cách / thời_gian > tốc_độ_máy_bay`. Hệ thống của em **không có** dữ liệu GeoIP.

Điểm cần ghi nhận: tiêu đề tiếng Việt trong file rule là *"Mot tai khoan dang nhap tu nhieu IP
khac nhau"* — mô tả đúng. Chỉ có `id: impossible_travel` là dùng nhầm thuật ngữ ngành.
[Đã kiểm chứng — `correlation/rules/smb_attack_chain.yml`]

**Tỷ lệ dương tính giả: em chưa đo.** Đây là thiếu sót thật, và em không biện minh. Về mặt suy
luận, các nguồn dương tính giả trong môi trường SME Việt Nam là:

1. Nhân viên đổi qua lại 4G ↔ Wi-Fi văn phòng ↔ VPN nhà — mỗi lần đổi là một IP mới.
2. IP động của FTTH gia đình đổi khi modem reconnect.
3. CGNAT của nhà mạng di động: cùng một người ra internet bằng nhiều IP công cộng trong một phiên.
4. Tài khoản dùng chung — rất phổ biến ở SME (`admin`, `ketoan`).

**Vì sao vẫn để `severity: high`?** Vì trường hợp 4 (tài khoản dùng chung) tuy không phải tấn
công nhưng **là vi phạm chính sách nghiêm trọng** ở doanh nghiệp — không truy vết được ai làm
gì. Alert này với SME có giá trị quản trị, không chỉ giá trị an ninh. Tuy vậy, dùng nhãn `high`
mà chưa có số liệu FP thì em đồng ý là chưa đủ căn cứ.

**Việc phải làm trước khi dùng thật:**

- Đổi `id` thành `concurrent_multi_ip_login` cho đúng bản chất.
- Chạy `scripts/benign_traffic.py` ít nhất 24 giờ để có FP rate thực đo.
- Bổ sung `exclude` cho dải IP LAN nội bộ và VPN công ty — đổi IP trong cùng dải nội bộ không
  mang thông tin.
- Nếu muốn đúng nghĩa impossible travel: bật GeoIP của Wazuh, thêm loại rule `velocity`.

### Câu 4 — `terms size: 50` để đếm cardinality và `MAX_BUCKETS = 500`

**Về `size: 50` trong `_run_distinct`:** nếu một tài khoản đăng nhập từ 300 IP, engine đếm ra
**50**, không phải 300. [Đã kiểm chứng — `engine.py`, agg `values` đặt `"size": 50`]

Hệ quả cụ thể: vì `min_cardinality = 3`, việc đếm hụt **không làm bỏ sót alert** — 50 vẫn ≥ 3
nên rule vẫn nổ. Cái sai nằm ở **bằng chứng**: trường `distinct_count` ghi 50 trong khi thực tế
300, và `distinct_values` chỉ liệt kê 50 IP. Analyst đọc alert sẽ đánh giá sai mức nghiêm trọng.

**Vì sao không dùng `cardinality` agg?** Câu trả lời thật: vì em cần **danh sách IP** để đưa vào
`evidence` cho analyst điều tra, mà `cardinality` chỉ trả một con số. Cách đúng là dùng **cả hai**:

```python
"aggs": {
  "keys": {
    "terms": {"field": rule.group_by, "size": MAX_BUCKETS},
    "aggs": {
      "total":  {"cardinality": {"field": rule.distinct_field}},          # dung cho nguong
      "sample": {"terms": {"field": rule.distinct_field, "size": 20}},    # dung lam bang chung
    },
  }
}
```

Phải nói rõ: `cardinality` của OpenSearch là **HyperLogLog++, xấp xỉ**, chính xác tuyệt đối chỉ
dưới `precision_threshold` (mặc định 3000). Với ngưỡng `min_cardinality: 3` thì sai số này không
ảnh hưởng.

**Về `MAX_BUCKETS = 500`:** `terms` agg sắp xếp theo `doc_count` giảm dần, trả về 500 bucket đầu.

- Với `noisy_agent_high_severity` (group theo `agent.name`, tìm máy ồn nhất): 500 bucket đầu
  **chính là** 500 máy ồn nhất — cắt bớt không gây bỏ sót cái ta cần tìm. [Suy luận]
- Với `mass_data_export_by_user` (group theo `data.dstuser`): nếu > 500 người dùng hoạt động
  trong cửa sổ 30 phút thì tài khoản ít alert hơn bị cắt. Nhưng `min_doc_count = rule.min_count = 5`
  đã lọc trước, chỉ khoá đạt ngưỡng mới vào danh sách — thực tế rất khó vượt 500. [Suy luận]

**Terms agg chính xác hay xấp xỉ?** Xấp xỉ **khi index có nhiều primary shard**, vì mỗi shard trả
top-N cục bộ rồi mới gộp. Một shard thì chính xác. Index `siem-correlated-*` đặt
`number_of_shards: 1` [Đã kiểm chứng — `correlation/siem_correlator/sinks.py`], nhưng
`wazuh-alerts-*` dùng template của Wazuh, em **chưa kiểm chứng** số shard:

```bash
curl -sk -u admin:SecretPassword "https://localhost:9200/_cat/indices/wazuh-alerts-*?v&h=index,pri,rep,docs.count"
```

Nếu `pri > 1`, cần thêm `"shard_size"` lớn hơn `size` trong agg để giảm sai số.

### Câu 5 — `doc_id` và nhân bản alert

Công thức: `bucket = int(window_end.timestamp()) // rule.window`, với `window_end = datetime.now()`
tại thời điểm chạy. [Đã kiểm chứng — `engine.py`, property `doc_id`]

**Diễn biến chính xác với `brute_force_then_success` (window 1800s, poll 60s):**

Giá trị `bucket` **không** đổi theo mỗi chu kỳ poll — nó đổi mỗi khi đồng hồ tường vượt một mốc
bội số của 1800 giây. Trong cùng một khối 1800 giây đó, mọi lần poll (30 lần) sinh **cùng một
`_id`** → ghi đè → 1 document.

Một chuỗi tấn công nằm trong cửa sổ trượt của truy vấn suốt 1800 giây kể từ lúc sự kiện xảy ra.
Một đoạn dài 1800 giây thì cắt qua **nhiều nhất một** mốc biên. Vậy:

> **Một chuỗi tấn công duy nhất sinh ra tối đa 2 document.**
> [Suy luận — suy ra từ số học của công thức, chưa chạy thực nghiệm đo]

**Cơ chế `_id` tất định thật sự chống được gì?** Chống nhân bản **trong phạm vi cùng một khối
thời gian**, tức chống được 29/30 bản trùng. Nó **không** chống được bản trùng khi vượt biên
khối. Em không nói nó chống nhân bản tuyệt đối.

**Nếu analyst thấy alert hiện 2 lần?** Hai document có `entity` và `correlation_rule` giống nhau,
chỉ khác `@timestamp`/`window_end`. Trên dashboard gộp được bằng cách nhóm theo
`correlation_rule` + `entity`. Cách sửa triệt để là đổi khoá băm từ mốc đồng hồ tường sang **mốc
của bằng chứng**:

```python
@property
def doc_id(self) -> str:
    # Neo theo su kien dau tien cua chuoi, khong theo dong ho tuong ->
    # cung mot chuoi tan cong luon cho ra cung mot _id, du chay lai luc nao.
    anchor = self.evidence.get("first_event_ts") or int(self.window_end.timestamp())
    raw = f"{self.rule.id}|{self.key}|{anchor}"
    return hashlib.sha1(raw.encode()).hexdigest()
```

---

## PHẦN II — Kiến trúc và vận hành

### Câu 6 — MTTD tệ nhất

| Mắt xích | Độ trễ | Căn cứ |
|---|---|---|
| Agent → manager | dưới 1s bình thường; tăng khi agent buffer đầy | mặc định Wazuh |
| `wazuh-analysisd` phân tích | mili-giây | — |
| **Rule tần suất của Wazuh** | tới hết `timeframe` | 100120: 120s; 100220: 60s [Đã kiểm chứng — `custom/rules/local_rules.xml`] |
| Filebeat → Indexer | ~1s | mặc định Filebeat |
| `refresh_interval` của index | ~1s | mặc định OpenSearch |
| **Chu kỳ quét của correlator** | tới 60s | `POLL_INTERVAL: "60"` [Đã kiểm chứng — `docker-compose.yml`] |

**MTTD tệ nhất cho alert tương quan ≈ 60s (poll) + ~2s (index) + tới 120s (rule tần suất) ≈ 3 phút.**
[Suy luận]

**Có chấp nhận được với ransomware không? Không, và em không giả vờ là có.** Ransomware mã hoá
xong một máy trạm trong vài phút. 3 phút phát hiện cộng thời gian con người phản ứng là quá muộn
để cứu dữ liệu trên máy đó.

**Nhưng phải phân biệt hai lớp phát hiện — đây là điểm em muốn hội đồng thấy rõ:**

- Lớp **Wazuh rule** phản ứng gần thời gian thực và **đã có active response**: rule 100120 và
  100220 kích hoạt lệnh `firewall-drop` chặn IP 600 giây, không cần đợi correlator.
  [Đã kiểm chứng — `ossec.conf`, khối `<active-response>`]
- Lớp **correlator** không nhắm vào chặn tức thời. Nó nhắm vào chuỗi hành vi trải hàng giờ
  (chiếm tài khoản → xuất dữ liệu), nơi độ trễ 60 giây so với cửa sổ 3600 giây là 1,7%.

Nói cách khác: correlator không phải công cụ ngăn chặn, nó là công cụ **phát hiện chuỗi và dựng
bằng chứng**. Dùng nó để chặn ransomware là dùng sai công cụ.

### Câu 7 — Sự kiện đến muộn

Cửa sổ truy vấn là `[now - window, now)`. [Đã kiểm chứng — `engine.py`, hàm `run`]

**Trả lời thẳng: nếu log đến muộn quá `window`, engine không bao giờ nhìn thấy nó.** Ví dụ: agent
mất mạng 2 giờ rồi gửi bù; rule `brute_force_then_success` có cửa sổ 30 phút; các sự kiện đó có
`@timestamp` cách hiện tại 2 giờ, nằm ngoài mọi cửa sổ truy vấn từ đó về sau → mất vĩnh viễn với
engine.

**Với log đến muộn dưới `window`** thì vẫn bắt được, vì cửa sổ trượt còn phủ.

**Em có cơ chế bù không? Chưa có — nhưng em đã dự trù chỗ cho nó.** Trong `config.py` có tham số
`lookback_slack` (mặc định 60 giây), **đọc từ biến môi trường nhưng chưa được `engine.py` dùng
tới**. [Đã kiểm chứng — `grep lookback_slack` chỉ ra 2 chỗ, cả hai đều trong `config.py`]

Đây là ý định thiết kế chưa hoàn thành, và em nói thật chứ không giấu. Cách hoàn thiện:

```python
def run(self, rule, now=None):
    end = (now or datetime.now(timezone.utc)) - timedelta(seconds=self.lookback_slack)
    start = end - timedelta(seconds=rule.window)
```

Dời cả cửa sổ lùi lại `lookback_slack` giây, đánh đổi thêm chừng đó độ trễ để nhận đủ log của mép
cửa sổ. Cách này chỉ xử lý được độ trễ nhỏ và đều. Với agent mất mạng dài thì cách duy nhất là
chuyển sang mô hình **watermark**: correlator lưu mốc đã xử lý, truy vấn theo `@timestamp` chứ
không theo đồng hồ tường, và tự chạy lại vùng có log đến muộn.

### Câu 8 — Lệch đồng hồ giữa các nguồn

**Em dùng trường `@timestamp` của index `wazuh-alerts-*`.** [Đã kiểm chứng — mọi truy vấn trong
`engine.py` đều `range` trên `@timestamp`]

Điểm quan trọng: trong Wazuh, `@timestamp` của alert là **thời điểm manager sinh ra alert**, không
phải thời điểm ghi trong bản thân dòng log. [Chưa kiểm chứng bằng thực nghiệm — kiểm tra bằng:]

```bash
curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-*/_search?size=1&sort=@timestamp:desc" | python -c "import sys,json; d=json.load(sys.stdin)['hits']['hits'][0]['_source']; print(d['@timestamp'],'|',d.get('full_log','')[:70])"
```

**Đây chính là điều khiến hệ thống miễn nhiễm phần lớn với lệch đồng hồ của endpoint.** Máy trạm
Windows lệch 5 phút hay router không có NTP đều không ảnh hưởng tới thứ tự trong rule `sequence`,
vì mọi mốc đều do **một** đồng hồ duy nhất — đồng hồ của manager — cấp phát.

**Cái nó đánh đổi:** thứ tự trong alert là thứ tự **manager nhận được**, không phải thứ tự **sự
việc thật xảy ra**. Nếu agent A gửi ngay còn agent B buffer 30 giây, chuỗi có thể bị đảo. Với rule
cửa sổ 30 phút–2 giờ, lệch 30 giây không ảnh hưởng; với chuỗi diễn ra trong vài giây thì có.

Bài học múi giờ ở README lưu ý 6 là chuyện khác hẳn: `<time>` của Wazuh **không đọc timestamp
trong log và cũng không theo `TZ` của container**, luôn so theo UTC. Đó là lỗi cấu hình, không
phải lỗi lệch đồng hồ; đã sửa bằng cách trừ 7 giờ khi ghi khung `<time>`, đổi 22:00–05:00 giờ VN
thành `15:00 - 22:00`. [Đã kiểm chứng — rule 100122 trong `custom/rules/local_rules.xml`]

### Câu 9 — Single-node cho SME

**a) Máy chủ chết lúc 2 giờ sáng thì mất bao nhiêu log?**

Trung thực: **mất toàn bộ log của khoảng thời gian chết, trừ phần agent giữ được trong buffer cục
bộ.** Agent Wazuh có hàng đợi cục bộ nên gửi bù được khi manager sống lại, nhưng hàng đợi hữu
hạn, đầy thì log bị bỏ. Thiết bị gửi syslog UDP (router, firewall) **không có bù gì cả** — UDP mất
là mất.

Đồng thời, như Câu 7, log gửi bù sau khi manager sống lại sẽ nằm ngoài cửa sổ trượt → correlator
không thấy. Nghĩa là mất khả năng phát hiện chứ không chỉ mất log.

Compose **có** đặt `restart: always` cho cả ba service Wazuh [Đã kiểm chứng — `docker-compose.yml`],
nên hỏng phần mềm thì tự lên lại. Hỏng phần cứng thì không.

**b) Chi phí phần cứng cho SME 50 endpoint?**

**Em không có số đo thực, nên không đưa ra con số bịa.** Cái em có là yêu cầu tối thiểu đã kiểm
chứng để stack chạy: RAM ≥ 6 GB cấp cho Docker, ổ trống ≥ 20 GB, Indexer heap 1 GB
(`-Xms1g -Xmx1g`). [Đã kiểm chứng — README mục 2 và `docker-compose.yml`]

Con số cho 50 endpoint phải **đo mới có**, vì phụ thuộc hoàn toàn vào việc bật những module nào.
Cấu hình hiện tại bật khá nhiều: FIM realtime trên `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`,
`/sbin`, `/boot`; rootcheck; SCA 12 giờ/lần; syscollector 1 giờ/lần; vulnerability-detection.
[Đã kiểm chứng — `ossec.conf`] Mỗi module đều sinh log đều đặn.

Em đã viết `scripts/measure_capacity.sh` để đo đúng ba con số cần thiết trên chính hệ thống đang
chạy: EPS thực, dung lượng mỗi ngày, và từ đó suy ra ổ đĩa cần cho N ngày lưu trữ. Cách trả lời
hội đồng là **đưa phương pháp đo và con số đo được trên môi trường lab**, kèm hệ số ngoại suy,
chứ không trích một con số từ tài liệu nhà cung cấp.

**c) SME không có SOC, ai đọc dashboard?**

Câu hỏi đúng chỗ đau nhất của mọi đồ án SIEM, và trả lời trung thực là: **nếu chỉ có dashboard
thì không ai đọc cả.**

Kiến trúc hiện tại đã có hai đường thoát khỏi mô hình "phải có người ngồi nhìn":

1. **Active response tự động** — rule 100120 (brute force) và 100220 (quét cổng) tự chặn IP 600
   giây, không cần người. [Đã kiểm chứng — `ossec.conf`]
2. **`ManagerSink`** — đẩy alert tương quan ngược vào socket manager để rule 100901/100902/100903
   bắt lại, từ đó dùng được `email_notification` và active response của Wazuh.
   [Đã kiểm chứng — `correlation/siem_correlator/sinks.py`, `custom/rules/local_rules.xml`]

Nhưng phải nói rõ giới hạn: `<email_notification>no</email_notification>` trong `ossec.conf` —
**email đang tắt**; và `MANAGER_SOCKET` **không được đặt** trong `docker-compose.yml` nên
`ManagerSink` **không hoạt động** ở cấu hình mặc định hiện tại. [Đã kiểm chứng]

Nghĩa là ở trạng thái hiện tại của repo, đường ra duy nhất tới con người là dashboard. Muốn dùng
thật ở SME thì việc bắt buộc phải làm là: bật email hoặc webhook Telegram/Zalo cho alert
`critical`, và định nghĩa rõ ai nhận. Em ghi nhận đây là việc chưa xong.

### Câu 10 — Đặc quyền tối thiểu cho correlator

**Hiện trạng, không giấu gì:**

- `INDEXER_USERNAME: admin` — correlator chạy bằng tài khoản quản trị toàn Indexer.
  [Đã kiểm chứng — `docker-compose.yml`, `config.py`]
- `INDEXER_VERIFY_CERTS: "false"` và `urllib3.disable_warnings(...)` — không xác thực chứng chỉ
  TLS. [Đã kiểm chứng — `indexer.py`]
- Cổng 9200 và 443 bind ra host; cổng API manager map `55500:55000`.
  [Đã kiểm chứng — `docker-compose.yml`]

**Correlator thực sự cần quyền gì?** Đọc code ra đúng bốn thao tác:

| Thao tác | Ở đâu | Quyền tối thiểu |
|---|---|---|
| `GET /` | `IndexerClient.ping` | `cluster:monitor/main` |
| `POST /wazuh-alerts-*/_search` | `search` | `read` trên `wazuh-alerts-*` |
| `PUT /siem-correlated-*/_doc/<id>` | `index_doc` | `write`, `create_index` trên `siem-correlated-*` |
| `PUT /_index_template/siem-correlated` | `ensure_index_template` | `indices:admin/index_template/put` |

Tức là: **chỉ đọc trên `wazuh-alerts-*`, chỉ ghi trên `siem-correlated-*`**. Không cần xoá, không
cần đụng cấu hình security, không cần quyền trên bất kỳ index nào khác.

```yaml
# roles.yml - vai tro dung cho correlator
siem_correlator:
  cluster_permissions:
    - "cluster:monitor/main"
    - "indices:admin/index_template/put"
  index_permissions:
    - index_patterns: ["wazuh-alerts-*"]
      allowed_actions: ["read", "search"]
    - index_patterns: ["siem-correlated-*"]
      allowed_actions: ["create_index", "write", "index"]
```

**Vì sao chuyện này quan trọng:** SIEM là nơi cất toàn bộ dấu vết an ninh của doanh nghiệp. Kẻ tấn
công chiếm được tài khoản `admin` của Indexer là **xoá sạch được bằng chứng về chính mình**.
Correlator là tiến trình chạy liên tục, có mật khẩu nằm trong biến môi trường của container — nếu
nó bị chiếm mà nó đang cầm quyền `admin` thì mất tất cả. Với vai trò tối thiểu ở trên, kẻ tấn công
chiếm được correlator chỉ đọc được alert và ghi bẩn vào `siem-correlated-*`, **không xoá được gì**.

Em đã ghi cảnh báo ở README mục 10, nhưng cảnh báo bằng chữ không thay được cấu hình.

### Câu 11 — Toàn vẹn log làm bằng chứng

**Trả lời thẳng: hệ thống hiện tại không chứng minh được tính toàn vẹn của log, và em không nên
trình bày alert của nó như bằng chứng pháp lý.**

Những thứ **không có**:

- Không ký số alert.
- Không lưu trữ WORM (ghi một lần, không sửa được).
- Không hash chain giữa các bản ghi.
- `<logall>no</logall>` và `<logall_json>no</logall_json>` — **không giữ log thô**, chỉ giữ alert.
  [Đã kiểm chứng — `ossec.conf`] Mất luôn khả năng đối chiếu ngược về dòng log gốc.
- Ai có quyền `admin` trên Indexer đều sửa hoặc xoá được document.

Với kịch bản `insider`, alert của hệ thống này có giá trị là **manh mối để bắt đầu điều tra**,
không phải bằng chứng. Muốn thành bằng chứng cần tối thiểu: bật `logall_json`, đẩy bản sao log thô
sang kho chỉ-ghi-thêm ngoài tầm tay quản trị viên SIEM, và ký số theo lô. Em không cài đặt phần
này trong phạm vi đồ án.

---

## PHẦN III — Phương pháp và đánh giá

### Câu 12 — Kiểm chứng vòng tròn

**Em thừa nhận: đúng là vòng tròn, và em không tranh cãi điểm này.**

`scripts/simulate_attack.py` do em viết sinh log theo đúng định dạng mà
`custom/decoders/local_decoder.xml` do em viết bóc tách, để `custom/rules/local_rules.xml` do em
viết bắt. Kết quả "9/9 kịch bản phát hiện thành công" chứng minh **chuỗi xử lý hoạt động thông
suốt**, chứ không chứng minh **hệ thống phát hiện được tấn công thật**.

**Nhưng cần phân biệt ba mảng, vì mức độ vòng tròn không giống nhau:**

| Mảng | Có vòng tròn không | Vì sao |
|---|---|---|
| Log ứng dụng ERP (`erpapp`) | **Có, hoàn toàn** | Định dạng do em tự định nghĩa. Không có ứng dụng ERP thật. |
| Log firewall (`portscan`, `scan-then-login`) | **Ít hơn** | Sinh log iptables đúng định dạng thật, **decoder là decoder `kernel` có sẵn của Wazuh**, không phải của em. [Đã kiểm chứng — `scripts/simulate_attack.py`, hàm `ev_fw_drop`] |
| Rule tương quan | **Có** | Rule YAML lọc theo `rule.id` do em đặt. |

Mảng thứ hai có giá trị cao hơn hẳn vì nó chứng minh engine tương quan **nối được hai nguồn log
khác nhau** (firewall + ứng dụng) qua `data.srcip`, và một nửa chuỗi đó dùng ruleset của Wazuh chứ
không phải của em.

**Em có chạy trên dataset độc lập không? Không.** Đây là giới hạn của đồ án và em nêu thẳng trong
chương giới hạn. Lý do: log ứng dụng ERP nội bộ theo định nghĩa là **không có** trong các dataset
công khai (CICIDS, UNSW-NB15 đều là lưu lượng mạng, không có log tầng ứng dụng nghiệp vụ).

**Hướng làm cho kết quả có giá trị hơn, trong tầm tay:**

1. Đo false positive trên lưu lượng lành tính — `scripts/benign_traffic.py`, làm được ngay và làm
   thay đổi hẳn chất lượng chương đánh giá.
2. Dùng `hydra`/`nmap` thật đánh vào một container SSH có agent, thay vì tự sinh log SSH — khi đó
   decoder là của Wazuh, log là thật, chỉ rule tương quan là của em.
3. Nhờ một người khác viết kịch bản tấn công mà không cho xem rule, rồi đo xem bắt được bao nhiêu
   — kiểm thử mù, phá vòng tròn ở mắt xích quan trọng nhất.

### Câu 13 — Không có false positive rate

**Thầy nói đúng hoàn toàn, và em đồng ý với cách gọi tên: cái em đang có là kiểm thử chức năng,
không phải đánh giá hiệu quả phát hiện.**

Chín kịch bản đều là true positive. Không có Precision, không có F1, vì thiếu vế FP.

**Chương "Kiểm thử và đánh giá" nên trình bày bằng các chỉ số sau:**

| Chỉ số | Công thức | Cách lấy số |
|---|---|---|
| Recall (độ phủ) | TP / (TP + FN) | 9 kịch bản tấn công, đếm kịch bản có alert đúng |
| **Precision (độ chính xác)** | TP / (TP + FP) | chạy `benign_traffic.py`, mọi alert sinh ra đều là FP |
| F1 | 2·P·R / (P+R) | từ hai số trên |
| **FP/ngày/endpoint** | số alert FP ÷ số ngày ÷ số endpoint | chỉ số SME quan tâm nhất |
| MTTD | thời điểm alert − thời điểm sự kiện đầu | `window_start` so với `@timestamp` của alert |

Chỉ số thứ tư là chỉ số **quan trọng nhất với đề tài này**. Một SME 50 máy chịu được chừng vài
alert mỗi ngày. Nếu hệ thống sinh 200 alert/ngày thì dù Recall 100% nó vẫn vô dụng, vì không ai đọc.

Em đã viết `scripts/eval_detection.py` để đo đủ bộ chỉ số này.

### Câu 14 — Ngưỡng lấy từ đâu

**Trung thực: các ngưỡng được chọn theo suy đoán nghiệp vụ và điều chỉnh cho demo chạy được,
không phải từ đo đạc trên dữ liệu thật.** Em không có dữ liệu vận hành của một SME thật để hiệu
chỉnh.

Một số ngưỡng **bị ràng buộc bởi kỹ thuật**, không phải chọn tự do:

- 100220 quét cổng: `frequency=15 timeframe=60`. Kịch bản demo gửi 20 sự kiện với `--delay <= 1.0`;
  delay lớn hơn thì sự kiện tràn ra ngoài cửa sổ 60 giây và rule không nổ.
  [Đã kiểm chứng — README mục 8 và `scenario_portscan`]
- 100121 spraying: `frequency=8` với `<different_field>dstuser</different_field>` nên **bắt buộc**
  phải có ít nhất 9 tên tài khoản khác nhau; danh sách `USERS` có 10 tên.
  [Đã kiểm chứng — comment trong `scripts/simulate_attack.py`]

**Về job ETL xuất dữ liệu 20 lần mỗi đêm:** rule `mass_data_export_by_user` ngưỡng 5 lần/30 phút sẽ
nổ **mỗi đêm**, thành nhiễu nền, và sau một tuần thì không ai còn đọc alert đó nữa — đây chính là
cơ chế "alert fatigue" giết chết SIEM trong thực tế.

Engine hiện tại **không có cơ chế allowlist** — không có `exclude` trong định nghĩa rule.
[Đã kiểm chứng — `CorrelationRule` trong `rules.py` chỉ có `filter`, không có trường loại trừ]

Cách sửa nhỏ nhưng đúng — thêm `must_not` vào rule YAML:

```python
# rules.py: them truong
exclude: dict[str, Any] = field(default_factory=dict)

# engine.py: dua vao query
"query": {"bool": {
    "filter": build_filter(rule.filter) + [_time_range(start, end)],
    "must_not": build_filter(rule.exclude),
}}
```

```yaml
# smb_attack_chain.yml
- id: mass_data_export_by_user
  filter:
    rule.id: ["100130", "100131"]
  exclude:
    data.dstuser: ["svc_etl", "svc_backup"]   # tai khoan dich vu, khong phai nguoi
```

Cách hiệu chỉnh ngưỡng đúng phương pháp: chạy hệ thống ở chế độ chỉ ghi nhận trong 2 tuần, lấy
phân vị 99 của từng chỉ số làm ngưỡng khởi điểm, rồi tinh chỉnh. Đó là việc của giai đoạn triển
khai thật, không nằm trong phạm vi đồ án — nhưng phải nói ra là mình biết.

### Câu 15 — Wazuh làm được rồi thì engine để làm gì

Em chỉ ra **đúng một** điểm không thể thay thế:

> **Wazuh không có nguyên thuỷ "đếm số giá trị KHÁC NHAU của một trường".**

Ruleset của Wazuh có `<frequency>` (đếm số lần), `<same_field>`/`<same_source_ip>`/`<same_user>`
(bắt giá trị **giống nhau**), và `<different_field>` (bắt giá trị **khác lần trước**). Cái nó
**không** có là *"đếm xem có bao nhiêu giá trị phân biệt, so với một ngưỡng cardinality"*.

Đây chính là rule `impossible_travel`: **một tài khoản đăng nhập thành công từ ≥ 3 IP khác nhau
trong 15 phút.**

Vì sao Wazuh không diễn đạt được:

- `<different_field>srcip</different_field>` chỉ kiểm tra IP lần này **khác lần liền trước**. Một
  người luân phiên đúng 2 IP (A→B→A→B→A) sẽ thoả `different_field` ở mọi bước, đếm đủ `frequency`
  và nổ alert — trong khi cardinality thật chỉ là **2**, dưới ngưỡng, không đáng cảnh báo.
- Ngược lại: 3 lần đăng nhập từ A, A, B, C — `different_field` gãy ở bước A→A, chuỗi đếm bị reset,
  trong khi cardinality thật là **3**, đúng ngưỡng, đáng cảnh báo.

Hai trường hợp này Wazuh cho kết quả **ngược** với cái ta cần. Engine của em dùng đúng phép toán
cần thiết — đếm giá trị phân biệt trong cửa sổ — nên cho kết quả đúng ở cả hai.
[Suy luận — suy ra từ ngữ nghĩa `different_field` của Wazuh; nên kiểm chứng bằng `wazuh-logtest`
trước buổi bảo vệ]

Về rule 40112 mà thầy nhắc: đúng, đó là rule composite có sẵn của Wazuh, và em **dùng lại nó có ý
thức** chứ không viết lại — comment trong file rule ghi rõ lý do: với SSH thật thì 5715 không phát
mà 40112 phát, và 40112 có sẵn `data.srcip` để join. [Đã kiểm chứng —
`correlation/rules/smb_attack_chain.yml`] Đây là quan điểm thiết kế: engine **không thay thế**
Wazuh, nó nhận đầu vào từ Wazuh và làm phần Wazuh không làm được.

### Câu 16 — Hai bản engine Python và Node

**Bản chạy thật là bản Python.** `docker-compose.yml` đặt `build.context: ../../correlation`.
[Đã kiểm chứng]

`correlation-node/` là **bản port 1:1 sang Node.js**, ghi rõ ngay dòng đầu
`correlation-node/README.md`, kèm bảng ánh xạ từng file sang file Python tương ứng. Rule YAML
**không nhân bản** — cả hai bản đều trỏ về `correlation/rules/`. [Đã kiểm chứng]

**Bảo đảm hai bản cùng hành vi bằng cách nào?** Có cơ chế cụ thể, không phải nói suông: test của
bản Node kiểm chứng `_id` của alert bằng **giá trị lấy từ bản Python**. Vì `_id` là SHA-1 của
`rule.id|key|bucket`, hai bản trùng `_id` nghĩa là trùng cả cách phân giải rule, cách xác định
khoá, và cách tính khối thời gian. Hệ quả thực tế: hai bản chạy song song **không sinh alert trùng
của nhau**, vì cùng `_id` thì ghi đè. [Đã kiểm chứng — `correlation-node/README.md`, mục "Khác
biệt so với bản Python", điểm 2]

**Khác biệt đã biết, README tự khai báo:**

1. `ManagerSink` bản Node phải gọi `socat` vì Node không hỗ trợ unix datagram socket (`net` chỉ
   `SOCK_STREAM`, `dgram` chỉ UDP). README **tự đánh dấu `[Chưa kiểm chứng]`** cho đường này và
   khuyến nghị dùng bản Python nếu bật `MANAGER_SOCKET`.
2. Định dạng timestamp khác nhau về hình thức (`+00:00` với `.000Z`), cả hai đều hợp
   `strict_date_optional_time`.

**Cái nào là sản phẩm của đồ án:** bản Python là sản phẩm chính, được compose dựng và được dùng
cho toàn bộ kết quả kiểm thử trong báo cáo. Bản Node là phần chứng minh kiến trúc không phụ thuộc
ngôn ngữ — rule YAML là hợp đồng, engine là chi tiết cài đặt. Trong báo cáo em nêu đúng vai trò
đó chứ không tính nó thành hai sản phẩm.

### Câu 17 — Phủ MITRE ATT&CK

**Rule tương quan gắn 5 kỹ thuật:** T1110 (Brute Force), T1078 (Valid Accounts), T1567
(Exfiltration Over Web Service), T1046 (Network Service Discovery), T1543 (Create or Modify System
Process). [Đã kiểm chứng — `smb_attack_chain.yml`]

Nhưng chỉ đếm 5 kỹ thuật là **đánh giá thấp hệ thống**, vì bên dưới còn ruleset gốc của Wazuh và
các module đang bật trong `ossec.conf`:

| Module | Trạng thái | Phủ giai đoạn nào |
|---|---|---|
| `syscheck` (FIM) realtime trên `/etc`, `/bin`, `/sbin`, `/boot` | bật | Persistence, Defense Evasion (một phần) |
| `rootcheck` | bật, 12 giờ/lần | Rootkit, Persistence |
| `sca` (CIS benchmark) | bật, 12 giờ/lần | Hardening — phòng ngừa, không phải phát hiện |
| `syscollector` | bật, 1 giờ/lần | Inventory — nền cho điều tra |
| `vulnerability-detection` | bật | Quản lý lỗ hổng |

[Đã kiểm chứng — `ossec.conf`]

**Những chỗ hệ thống MÙ HẲN — em nêu thẳng:**

1. **Lateral Movement (TA0008).** Không có rule nào theo dõi di chuyển ngang. Cần Windows Security
   Event 4624 type 3, 4648, 4776 và một rule tương quan kiểu "một tài khoản đăng nhập vào N máy
   khác nhau trong M phút" — với engine hiện tại đây **là rule `distinct` viết được ngay**, group
   theo `data.dstuser`, distinct theo `agent.name`. Hướng mở rộng rõ ràng nhất.
2. **Command & Control / beaconing (TA0011).** Hoàn toàn mù. Phát hiện beaconing cần phân tích chu
   kỳ kết nối trên netflow — hệ thống **không thu thập netflow**, chỉ nhận log. Engine cũng không
   có loại rule phân tích chu kỳ.
3. **Persistence (TA0003).** Chỉ phủ một phần qua FIM và rootcheck. Không theo dõi scheduled task,
   service mới, registry Run key trên Windows.
4. **Defense Evasion (TA0005).** Không phát hiện xoá log — hành vi gần như chắc chắn của kẻ tấn
   công có kinh nghiệm. Chưa có rule bắt event xoá Security log của Windows (Event ID 1102).
5. **Rootcheck và SCA chạy 12 giờ/lần** — quét định kỳ, không phải phát hiện thời gian thực.
   [Đã kiểm chứng — `<frequency>43200</frequency>`]

**Định vị trung thực:** hệ thống phủ tốt giai đoạn **Initial Access / Credential Access /
Collection / Exfiltration** trên các nguồn log được cấu hình, và mù ở **Lateral Movement / C2 /
phần lớn Persistence**. Với SME — nơi phần lớn sự cố là brute force RDP, lộ mật khẩu, và nhân viên
lấy dữ liệu — phần được phủ đúng là phần hay xảy ra nhất. Nhưng nói "triển khai SIEM" mà ngụ ý phủ
toàn diện thì là nói quá.

---

## PHẦN IV — Trả lời các tình huống

Mỗi tình huống có script tương ứng. Lệnh chạy: xem `docs/kich-ban-hoi-dong.md`.

### Tình huống A — Bão alert  (script: `scripts/benign_traffic.py --storm`)

Kịch bản: 200 nhân viên, mỗi người 1 lần `FAILED` rồi 1 lần `OK`, trong 15 phút.

| Rule | Có nổ không | Vì sao |
|---|---|---|
| 100111 (đăng nhập thất bại) | **Có, 200 lần** | mỗi lần FAILED là 1 alert level 5 |
| 100110 (đăng nhập thành công) | **Có, 200 lần** | level 3, vẫn ghi vì `log_alert_level` là 3 |
| 100120 (brute force) | **Không** | cần `frequency=6` lần thất bại **cùng user cùng IP** trong 120s; mỗi người chỉ sai 1 lần |
| 100121 (spraying) | **Không** | cần 8 user khác nhau **cùng một IP**; 200 người là 200 IP khác nhau |
| `brute_force_then_success` | **Không** | stage `do_mat_khau` lọc `rule.id` trong `["100120","100121","5710","5712","60122"]` — **không** chứa 100111 |
| `noisy_agent_high_severity` | **Không** | ngưỡng 20 alert `level >= 10`; 100111 chỉ level 5 |

**Kết luận quan trọng:** rule tương quan `brute_force_then_success` **không** nổ 200 lần, vì giai
đoạn 1 của nó yêu cầu alert **brute force đã được Wazuh xác nhận** (100120/100121), không phải từng
lần thất bại lẻ. [Đã kiểm chứng — `smb_attack_chain.yml`]

Đây là lựa chọn thiết kế đúng mà em muốn hội đồng thấy: **xây rule tương quan trên alert đã tổng
hợp, không trên sự kiện thô** — chính là lớp chống bão alert tự nhiên.

Thứ thật sự gây phiền là **400 alert Wazuh thô** trên Threat Hunting — nhiễu nền, không phải bão
alert tương quan.

**Cơ chế chống bão alert nằm ở đâu trong code?** Ba lớp có sẵn, một lớp còn thiếu:

1. **Xây rule trên alert đã tổng hợp** — lớp mạnh nhất.
2. **`_id` tất định** — chống nhân bản trong cùng khối thời gian. [Đã kiểm chứng — `engine.py`]
3. **`min_doc_count` đẩy xuống Indexer** — bucket không đạt ngưỡng bị loại ngay ở tầng agg.
   [Đã kiểm chứng]
4. **Thiếu: allowlist / exclude** — xem Câu 14. Lỗ hổng thật khi gặp job tự động.

### Tình huống B — Kẻ tấn công biết ngưỡng  (script: `scripts/evade_thresholds.py`)

Chiến thuật: 5 lần sai/130 giây, đổi IP mỗi 2 lần thử, xuất dữ liệu 4 lần/30 phút.

| Rule | Ngưỡng | Kết quả |
|---|---|---|
| 100120 brute force | 6 lần/120s, **cùng IP cùng user** | **né được** — đổi IP mỗi 2 lần |
| 100121 spraying | 8 user khác nhau/300s, **cùng IP** | **né được** — chỉ nhắm 1 user |
| `mass_data_export_by_user` | 5 lần/1800s | **né được** — chỉ 4 lần |
| `brute_force_then_success` | cần 100120 hoặc 100121 ở stage 1 | **né được** — hai rule trên không nổ thì stage 1 rỗng |
| 100111 (thất bại lẻ) | không có ngưỡng | **vẫn nổ** — nhưng chỉ level 5, chìm trong nhiễu |
| 100131 xuất hàng loạt | rows ≥ 10000, **không có ngưỡng tần suất** | **vẫn nổ**, level 10 — nếu xuất > 10000 dòng |

**Kết luận trung thực: kẻ tấn công biết ngưỡng thì né được gần hết lớp tương quan.** Chỉ còn 100131
bắt được, và chỉ khi hắn xuất nhiều dòng — chia nhỏ dưới 10000 là né nốt.

**Phản biện về tính bền vững của phát hiện dựa-trên-ngưỡng:**

Đây là **giới hạn cố hữu của mọi hệ thống dựa trên luật**, không riêng đồ án này — sản phẩm thương
mại cũng vậy. Ngưỡng tĩnh luôn có thể né nếu biết giá trị. Nhưng cần nói rõ ba điều:

1. **Chi phí của kẻ tấn công tăng rõ rệt.** Từ một cuộc brute force xong trong 2 phút thành chiến
   dịch kéo dài hàng giờ, cần hạ tầng nhiều IP. Với SME, phần lớn tấn công là **cơ hội, tự động,
   không nhắm mục tiêu** — bot quét cả internet không dừng lại để đọc đồ án tốt nghiệp của ai.
2. **Repo public là con dao hai lưỡi thật.** Nếu triển khai thật thì ngưỡng phải nằm ngoài mã nguồn
   công khai, hoặc sinh ngẫu nhiên quanh giá trị trung tâm — ngưỡng biến thiên thì không né chính
   xác được.
3. **Hướng đi đúng để giảm phụ thuộc ngưỡng là baseline hành vi** (Câu 18) — so với thói quen của
   chính người đó, không so với một hằng số. Kẻ tấn công không biết baseline của nạn nhân.

### Tình huống C — Nội gián im lặng  (script: `scripts/slow_insider.py`)

**Hệ thống có phát hiện không? KHÔNG, và không có cách nào phát hiện với kiến trúc hiện tại.**

| Rule | Vì sao trượt |
|---|---|
| `mass_data_export_by_user` | ngưỡng 5 lần/30 phút; nội gián làm 1 lần/ngày |
| 100131 xuất hàng loạt | chỉ nổ nếu ≥ 10000 dòng; 1 báo cáo khách hàng thường ít hơn |
| 100122 ngoài giờ | đăng nhập trong giờ hành chính |
| `impossible_travel` | 1 IP duy nhất, đúng máy của mình |
| `account_takeover_to_exfil` | không có giai đoạn dò mật khẩu |

Sâu xa hơn: **cửa sổ dài nhất trong toàn hệ thống là 7200 giây (2 giờ)** — rule
`privilege_then_config_change`. [Đã kiểm chứng — `smb_attack_chain.yml`] Hành vi trải 60 ngày nằm
ngoài tầm nhìn của mọi rule, về mặt **kiến trúc** chứ không phải về mặt tinh chỉnh ngưỡng.

**Cần thêm gì:**

1. **Baseline theo người dùng (UEBA).** Với mỗi tài khoản, tính trung bình và độ lệch chuẩn số dòng
   xuất mỗi ngày trong 30 ngày. Cảnh báo khi vượt `mean + 3σ`. Bắt được **thay đổi hành vi**, không
   cần ngưỡng tuyệt đối.
2. **So sánh theo nhóm tương đương (peer group).** Nếu 10 kế toán viên khác xuất trung bình 2 báo
   cáo/tuần mà người này xuất 7/tuần thì bất thường — dù con số tuyệt đối vẫn nhỏ.
3. **Cửa sổ dài, tổng tích luỹ.** Thêm loại rule `cumulative`: tổng `erp.rows` theo `data.dstuser`
   trong 30 ngày, cảnh báo khi vượt ngưỡng. Đây là thay đổi **nhỏ** với engine — chỉ cần thêm `sum`
   agg và cho phép `window` lớn.
4. **Ngữ cảnh nhân sự.** Ghép với ngày nộp đơn nghỉ việc từ hệ thống HR — tín hiệu mạnh nhất, nhưng
   đòi hỏi tích hợp ngoài phạm vi SIEM.

Trong bốn hướng, **hướng 3 là hướng em làm được ngay** với kiến trúc hiện tại, và em nêu nó trong
chương hướng phát triển.

### Tình huống D — Dashboard tương quan trống lúc demo  (script: `scripts/troubleshoot_demo.sh`)

Chẩn đoán theo thứ tự từ rẻ đến đắt.

**1. Chưa tới chu kỳ quét (khả năng cao nhất, chi phí kiểm tra bằng 0).**

`POLL_INTERVAL` mặc định 60 giây. Alert Wazuh hiện ngay còn alert tương quan phải đợi tới một vòng
quét. Hành vi bình thường, không phải lỗi — chính script demo cũng in dòng nhắc này.

```bash
docker compose -f docker/single-node/docker-compose.yml logs --tail=20 correlator
```

Tìm dòng `Vong quet xong: N alert tuong quan`. Nếu `N=0` mà đã qua vòng quét thì sang bước 2.

**2. Correlator không kết nối được Indexer.**

```bash
docker compose -f docker/single-node/docker-compose.yml logs correlator | grep -i "Cho Wazuh Indexer\|Khong ket noi"
```

Thấy `Cho Wazuh Indexer... (n/30)` lặp lại nghĩa là `ping()` đang thất bại — sai mật khẩu, sai URL,
hoặc Indexer chưa init security. Kiểm tra trực tiếp:

```bash
curl -sk -u admin:SecretPassword https://localhost:9200/ | head -5
```

Trả `OpenSearch Security not initialized` thì chạy `securityadmin.sh` như README mục 3.

**3. Rule không nạp được.**

`load_rules` bắt lỗi từng file và **chỉ ghi log rồi bỏ qua**, engine vẫn chạy tiếp — nên lỗi YAML
không làm correlator chết, chỉ làm nó chạy với ít rule hơn. [Đã kiểm chứng — `rules.py`, khối
`except`]

```bash
docker compose -f docker/single-node/docker-compose.yml logs correlator | grep -i "Nap .* rule\|Bo qua"
```

Phải thấy `Nap 7 rule tuong quan`. Ít hơn 7 hoặc thấy `Bo qua ...` nghĩa là file YAML lỗi.

**4. Có finding nhưng ghi vào Indexer thất bại.**

```bash
docker compose -f docker/single-node/docker-compose.yml logs correlator | grep -i "Ghi alert that bai\|Tao index template"
curl -sk -u admin:SecretPassword "https://localhost:9200/siem-correlated-*/_count"
```

`_count` > 0 mà dashboard trống thì **không phải lỗi correlator** — mà là index pattern chưa tạo
trên Dashboard, hoặc bộ lọc thời gian của dashboard đang ở khoảng quá khứ. Lỗi hay gặp nhất lúc
demo và cũng dễ sửa nhất.

**5. Nguyên nhân ngoài bốn cái trên, hay gặp trong demo:** `--delay` để quá lớn. Delay > 1.0 thì
rule tần suất của Wazuh (100120: 6 lần/120s) **không nổ**, kéo theo stage 1 của
`brute_force_then_success` rỗng nên rule tương quan không có gì để nối. Triệu chứng đặc trưng: thấy
100111 nhưng **không** thấy 100120. [Đã kiểm chứng — README mục 8 và docstring của
`simulate_attack.py`]

`scripts/troubleshoot_demo.sh` chạy tự động cả năm bước.

### Tình huống E — Giám đốc hỏi tiền  (script: `scripts/measure_capacity.sh`)

Trả lời 60 giây:

> "Anh đang trả 0 đồng, và đang chấp nhận rủi ro là **không biết mình bị tấn công**. Trung bình một
> doanh nghiệp mất hàng tháng mới phát hiện ra bị xâm nhập — trong lúc đó dữ liệu khách hàng đã ra
> ngoài.
>
> **Anh được gì:** một máy chủ ghi lại toàn bộ hoạt động đăng nhập, truy xuất dữ liệu và thay đổi
> cấu hình của cả công ty. Khi có sự cố, anh biết ai làm, lúc nào, từ máy nào — thay vì đoán. Ba
> việc nó tự làm không cần người: chặn IP dò mật khẩu trong 10 phút, cảnh báo khi một tài khoản
> xuất dữ liệu bất thường, và phát hiện khi tài khoản của anh đăng nhập từ nhiều nơi cùng lúc.
>
> **Anh mất gì:** một máy chủ — một máy cũ có 8 GB RAM, hoặc VPS chừng vài trăm nghìn một tháng.
> Phần mềm miễn phí, mã nguồn mở, không phí bản quyền. Và mất công của một người, **khoảng 30 phút
> mỗi tuần** để xem lại cảnh báo — không có người này thì hệ thống chỉ ghi log chứ không bảo vệ
> được ai.
>
> **Con số cụ thể của công ty anh** thì tôi phải đo mới nói được — chạy một tuần rồi đưa anh số
> dung lượng thật và số cảnh báo thật mỗi ngày. Tôi không muốn đưa anh con số lấy từ tài liệu quảng
> cáo."

Điểm mấu chốt khi trả lời hội đồng: **thành thật ở chỗ chi phí con người**. SIEM không phải sản
phẩm cắm-là-chạy. Ai nói với giám đốc rằng lắp vào là xong thì đang bán hàng, không phải làm kỹ
thuật.

### Tình huống F — Rule sai hướng (`^OK$`)  (script: `scripts/negative_rule_test.sh`)

**Phát hiện bằng cách nào:** khi chạy kịch bản `full` để kiểm thử, alert `brute_force_then_success`
nổ ở những chuỗi mà em biết chắc là **đăng nhập bị chặn**. Đối chiếu ngược từ alert tương quan về
rule 100110, rồi về decoder, mới thấy `<status>OK</status>` không neo `^...$` nên khớp cả `NOTOK`,
`TOKEN_EXPIRED`, `BLOCKED`. [Đã kiểm chứng — README mục 5, lưu ý 4]

Đây là **loại lỗi nguy hiểm nhất trong đồ án này**: nó không làm hệ thống báo lỗi, không làm rule
không nổ — nó làm rule nổ **với kết luận ngược hoàn toàn**. Tấn công bị chặn thành công lại được
báo là "tài khoản đã bị chiếm". Nếu doanh nghiệp hành động theo alert đó thì khoá nhầm tài khoản
của người dùng thật.

**Phát hiện sau bao lâu:** trong giai đoạn kiểm thử, trước khi có kết quả nào đưa vào báo cáo.

**Còn bao nhiêu lỗi cùng loại chưa phát hiện? Em không biết — và đó chính là vấn đề.** Em không thể
tuyên bố đã hết, vì cách phát hiện lỗi này là **tình cờ khi đối chiếu thủ công**, không phải quy
trình.

**Quy trình đang có và giới hạn của nó:** `scripts/test_rules.sh` dùng `wazuh-logtest` để kiểm tra
log mẫu ra đúng rule id. Nhưng nó là **kiểm thử dương tính**: đưa log đúng, xác nhận rule nổ. Nó
**không** bắt được lỗi loại này, vì lỗi loại này là **dương tính giả**: log sai lại làm rule nổ.

**Quy trình đúng cần bổ sung — kiểm thử âm tính.** Với mỗi rule, ngoài log-phải-khớp còn phải có
danh sách **log-không-được-khớp**:

```
# 100110 = dang nhap THANH CONG. Nhung dong sau day KHONG duoc ra 100110:
AUTH result=NOTOK user=nvhung srcip=203.0.113.77 reason=bad_password path=/api/login
AUTH result=TOKEN_EXPIRED user=nvhung srcip=203.0.113.77 reason=expired path=/api/login
AUTH result=BLOCKED user=nvhung srcip=203.0.113.77 reason=locked path=/api/login
```

Nguyên tắc rút ra, áp dụng cho toàn bộ decoder/rule: **mọi phép so khớp trên trường trạng thái đều
phải neo `^...$`**. Đây là bài học tổng quát chứ không phải bản vá một chỗ.

`scripts/negative_rule_test.sh` cài đặt đúng quy trình kiểm thử âm tính đó.

### Tình huống G — Mở rộng từ 40 lên 400 endpoint

Thứ tự các nút thắt **vỡ trước, vỡ sau**:

**Nút 1 — Heap của Indexer (vỡ trước tiên).**

`OPENSEARCH_JAVA_OPTS: "-Xms1g -Xmx1g"` [Đã kiểm chứng — `docker-compose.yml`]. 1 GB heap là cấu
hình cho lab. Với 400 endpoint, số shard và bộ nhớ đệm truy vấn tăng tuyến tính; heap 1 GB sẽ liên
tục full GC rồi `OutOfMemoryError`. Triệu chứng: dashboard chậm dần rồi Indexer chết.
**Ngưỡng cụ thể: chưa kiểm chứng, phải đo bằng `_nodes/stats/jvm`.**

**Nút 2 — Truy vấn của correlator.**

Mỗi chu kỳ 60 giây, engine chạy 7 rule; rule `sequence` chạy 1 truy vấn cho mỗi giai đoạn. Tổng:
3 rule threshold/distinct (3 truy vấn) + 4 rule sequence (3 rule × 2 giai đoạn + 1 rule × 3 giai
đoạn = 9 truy vấn) = **12 truy vấn agg mỗi 60 giây**. [Suy luận — đếm từ `smb_attack_chain.yml` và `engine.py`]

Số truy vấn **không** tăng theo số endpoint (đó là ưu điểm của thiết kế agg), nhưng **chi phí mỗi
truy vấn** tăng theo lượng document phải quét. Đến một mức, một vòng quét kéo dài hơn
`POLL_INTERVAL` — lúc đó vòng lặp trong `__main__.py` chạy nối đuôi liên tục, correlator ngốn hết
CPU và cạnh tranh với chính Indexer trên cùng máy. Triệu chứng nhận biết: dòng log
`Vong quet xong: N alert tuong quan, X.Xs` với `X.X` tiến gần 60.

**Nút 3 — `MAX_BUCKETS = 500`.**

Với 400 endpoint thì group theo `agent.name` vẫn an toàn (400 < 500). Nhưng nếu có > 500 tài khoản
hoạt động đồng thời thì `mass_data_export_by_user` bắt đầu cắt bucket. [Suy luận]

**Nút 4 — Đĩa và tốc độ ghi.**

Tuyến tính theo số endpoint. Với FIM realtime bật trên 5 nhóm thư mục hệ thống, cộng SCA +
syscollector + vulnerability-detection, lượng log mỗi endpoint không nhỏ. Đo bằng
`scripts/measure_capacity.sh`, ngoại suy tuyến tính từ số đo lab.

**Nút 5 — `wazuh-analysisd` một tiến trình.**

Wazuh xử lý phân tích trên một node duy nhất, `<queue_size>131072</queue_size>` [Đã kiểm chứng —
`ossec.conf`]. Khi hàng đợi đầy, sự kiện bị **bỏ** chứ không xếp hàng. Ngưỡng EPS cụ thể phụ thuộc
CPU, phải đo.

**Kiến trúc cần đổi thành gì ở quy mô 400:** tách Indexer thành cluster ≥ 3 node có replica, tách
correlator sang máy riêng, tăng heap lên 50% RAM (tối đa 31 GB), và bật ISM policy để tự động
chuyển index cũ sang cold rồi xoá.

---

## PHẦN V — Câu hỏi đóng

### Câu 18 — Nếu làm lại thì đổi gì

**1. Đo false positive ngay từ tuần đầu, không để tới cuối.** Đây là thứ làm thay đổi bản chất
chương đánh giá, và nó **rẻ** — chỉ cần một script sinh lưu lượng lành tính chạy nền. Em để tới
cuối nên giờ chương đánh giá chỉ có kiểm thử chức năng. Nếu làm lại, `benign_traffic.py` sẽ là thứ
viết **trước** `simulate_attack.py`.

**2. Xác minh thứ tự bằng sự kiện thật ngay từ đầu, không dựa vào min/max.** Tối ưu bằng agg là
đúng cho tầng lọc thô, nhưng em đã dừng ở đó và coi nó là kết quả cuối. Thiết kế hai tầng (Câu 2)
không đắt hơn bao nhiêu mà chính xác hơn hẳn, và cho `evidence` tốt hơn nhiều.

**3. Đưa vào một loại rule `baseline` ngay từ thiết kế.** Bốn loại rule (`threshold`, `distinct`,
`sequence`, `baseline`) thay vì ba. Loại thứ tư mở ra toàn bộ nhóm kịch bản nội gián chậm — nhóm mà
SME dễ gặp nhất và hệ thống hiện tại mù hoàn toàn (Tình huống C).

Một điều em **không** đổi: quyết định xây rule tương quan trên **alert đã tổng hợp của Wazuh** thay
vì trên log thô. Đó là thứ giữ cho hệ thống không vỡ trong Tình huống A.

### Câu 19 — Phần nào tự viết

| Thành phần | Bản chất | Định lượng |
|---|---|---|
| Wazuh 4.x (manager, indexer, dashboard) | **Sản phẩm có sẵn**, cấu hình lại | ~3000 rule gốc |
| `docker/single-node/` | **Cấu hình**, dựa trên compose mẫu của Wazuh, sửa đáng kể | `ossec.conf` chỉnh nhiều mục |
| `custom/decoders/local_decoder.xml` | **Tự viết** | 1 decoder cha + 4 decoder con |
| `custom/rules/local_rules.xml` | **Tự viết** | 17 rule (100100–100903) |
| `correlation/siem_correlator/` | **Tự viết** | 645 dòng Python, 7 file |
| `correlation/rules/*.yml` | **Tự viết** | 7 rule tương quan |
| `correlation-node/` | **Tự viết** (port của bản trên) | 7 file JS |
| `scripts/simulate_attack.py` | **Tự viết** | 9 kịch bản |
| `dashboards/build_dashboard.py` | **Tự viết** | sinh saved object NDJSON |

**Định lượng trung thực:** phần tự viết là **decoder, ruleset ứng dụng, engine tương quan, rule
YAML, bộ kịch bản và dashboard**. Phần cấu hình lại sản phẩm có sẵn là **toàn bộ hạ tầng Wazuh**.

Nhưng có một ý mà bảng trên không thể hiện được: **phần lớn công sức thật không nằm ở số dòng code,
mà nằm ở 7 điểm vấp đã ghi trong README mục 5** — decoder con thiếu `<prematch>`, rule gốc không
được để level 0, hai rule tranh `if_matched_sid`, so khớp không neo `^...$`, `os_regex` không hiểu
`[1-9]`, `<time>` so theo UTC, analysisd thử rule anh em theo level giảm dần. Mỗi điểm là một hành
vi không có trong tài liệu Wazuh, chỉ tìm ra bằng thử-sai. Đó là đóng góp thực về tri thức triển
khai, dù không đếm được bằng dòng code.

### Câu 20 — Đã chạy ở đâu ngoài máy em chưa

**Chưa.** Hệ thống chạy trên Docker Desktop / Windows với WSL2, chưa triển khai ở doanh nghiệp thật
nào.

**Còn thiếu gì để đưa vào một doanh nghiệp thật ngày mai:**

*Bắt buộc, không có thì không được triển khai:*

1. Đổi toàn bộ mật khẩu mặc định (`SecretPassword` trong `.env`, hash bcrypt trong
   `internal_users.yml`).
2. Sinh lại chứng chỉ, bật `INDEXER_VERIFY_CERTS: "true"`.
3. Tạo vai trò đặc quyền tối thiểu cho correlator (Câu 10), bỏ `admin`.
4. Chỉ bind 9200 và cổng API vào `127.0.0.1`.
5. Thu hẹp `<allowed-ips>` từ ba dải riêng (`10/8`, `172.16/12`, `192.168/16`) xuống đúng LAN thật
   — hiện đang mở rất rộng. [Đã kiểm chứng — `ossec.conf`]

*Cần, không có thì hệ thống chỉ ghi log chứ không bảo vệ:*

6. Bật email hoặc webhook cho alert `critical`; đặt `MANAGER_SOCKET` để `ManagerSink` hoạt động.
7. Chạy 2 tuần ở chế độ quan sát, hiệu chỉnh ngưỡng và lập allowlist cho các job tự động (Câu 14).
8. Đặt chính sách lưu trữ (ISM policy) — hiện chưa có, index sẽ tăng vô hạn tới khi đầy đĩa.
9. Sao lưu định kỳ, và một quy trình khôi phục đã diễn tập.

*Nên có:*

10. Xác minh thứ tự bằng sự kiện thật (Câu 2).
11. Loại rule `baseline` cho kịch bản nội gián chậm (Tình huống C).
12. Bật `logall_json` và đẩy bản sao sang kho chỉ-ghi-thêm nếu cần dùng làm bằng chứng (Câu 11).

Nói ngắn: **hệ thống đã chứng minh được nguyên lý, chưa chứng minh được độ bền vận hành.** Đó là
ranh giới đúng của một đồ án tốt nghiệp, và em không muốn tuyên bố quá lên.
