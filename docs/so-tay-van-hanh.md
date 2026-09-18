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
