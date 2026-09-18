# Plan: Tích hợp `kaifcodec/user-scanner` vào SIEM

## 1. Mục tiêu

Tích hợp [`kaifcodec/user-scanner`](https://github.com/kaifcodec/user-scanner) vào SIEM hiện tại dưới vai trò **OSINT Enrichment Engine**, không biến scanner thành detection engine.

Mục tiêu chính:

1. Tự động trích xuất entity từ Alert/Finding.
2. Xác định entity phù hợp để OSINT enrichment: `email`, `username` và các entity được hỗ trợ ở các phase sau.
3. Gửi yêu cầu enrichment bất đồng bộ qua Kafka.
4. Chạy `user-scanner` trong một worker/service riêng.
5. Chuẩn hóa kết quả thành internal OSINT schema.
6. Lưu evidence và enrichment result.
7. Correlate OSINT evidence với Alert/Finding hiện có.
8. Tính confidence/risk bổ sung, nhưng **không tự động khẳng định hai profile thuộc cùng một người chỉ vì username giống nhau**.
9. Xuất OSINT Finding theo OCSF khi cần; giữ nguyên kiến trúc OCSF hiện tại của SIEM.

---

## 2. Nguyên tắc kiến trúc

### 2.1. Không nhúng scanner trực tiếp vào SIEM Core

Không làm:

```text
SIEM Core
  └── import user-scanner
```

Nên làm:

```text
SIEM Core
    |
    +--> Entity Extraction
    |
    +--> Kafka: enrichment.request
                 |
                 v
          OSINT Enrichment Worker
                 |
                 v
           user-scanner
                 |
                 v
          Normalize / Validate
                 |
                 v
          Kafka: enrichment.result
                 |
                 v
          Correlation / Finding
```

Lợi ích:

- Tách failure domain.
- Scanner có thể timeout/restart mà không làm SIEM Core chết.
- Có thể scale worker độc lập.
- Có thể thay scanner khác trong tương lai.
- Có thể kiểm soát rate limit và concurrency riêng.
- Dễ audit từng lần enrichment.

### 2.2. Scanner là enrichment, không phải detector

```text
Detection
    ↓
Alert
    ↓
Entity Extraction
    ↓
OSINT Enrichment
    ↓
Evidence
    ↓
Correlation
    ↓
Risk / Confidence
    ↓
Finding / Case
```

Không tạo alert chỉ vì scanner tìm thấy một username trên một website.

---

# 3. Phạm vi MVP

## In scope

- Email enrichment.
- Username enrichment.
- Manual scan từ UI/API.
- Automatic enrichment cho một số loại Alert được policy cho phép.
- Kafka request/result.
- Worker chạy `user-scanner`.
- Timeout, retry, dead-letter.
- Redis cache chống scan trùng.
- Normalize kết quả.
- Lưu raw result/evidence.
- Liên kết enrichment với Alert.
- Hiển thị enrichment trong Alert/Investigation.
- Audit log.
- Mapping OSINT result sang OCSF Finding nếu cần export.

## Out of scope ở MVP

- Tự động kết luận danh tính thật của một người.
- Tự động block user/domain/IP dựa riêng vào OSINT.
- Full identity graph.
- AI autonomous investigation.
- Scan tất cả Alert.
- Scan liên tục không có policy.
- Thay thế detection engine hiện tại.

---

# 4. Kiến trúc tổng thể

```text
                         ┌──────────────────────┐
                         │        SIEM          │
                         │                      │
Logs / Events ---------->│ Detection Engine     │
                         │         │            │
                         │         ▼            │
                         │       Alert          │
                         └─────────┬────────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │ Entity Extractor │
                         └────────┬─────────┘
                                  │
                         email / username
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Enrichment Policy│
                         └────────┬─────────┘
                                  │
                           allowed to scan?
                            /           \
                          no             yes
                          │               │
                          │               ▼
                          │       Kafka enrichment.request
                          │               │
                          │               ▼
                          │       ┌──────────────────┐
                          │       │ OSINT Worker      │
                          │       │                  │
                          │       │ user-scanner     │
                          │       └────────┬─────────┘
                          │                │
                          │                ▼
                          │        Normalize Result
                          │                │
                          │                ▼
                          │       enrichment.result
                          │                │
                          └────────┬───────┘
                                   ▼
                         ┌──────────────────┐
                         │ Correlation      │
                         │ Engine           │
                         └────────┬─────────┘
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
                    Risk/Confidence     Evidence
                         │                 │
                         └────────┬────────┘
                                  ▼
                         ┌──────────────────┐
                         │ Finding / Case   │
                         └────────┬─────────┘
                                  ▼
                            OpenSearch
                                  │
                                  ▼
                              Dashboard
```

---

# 5. Thành phần cần thêm

## 5.1. Entity Extractor

Input:

```json
{
  "alert_id": "alert-123",
  "username": "admin-company",
  "source": {
    "ip": "10.10.10.10"
  }
}
```

Output:

```json
{
  "entities": [
    {
      "type": "username",
      "value": "admin-company",
      "source": "alert.username"
    }
  ]
}
```

Entity model:

```text
Entity
├── type
├── value
├── source
├── confidence
└── first_seen
```

MVP:

```text
email
username
```

Phase sau:

```text
domain
URL
social profile
```

---

# 6. Enrichment Policy

Không scan tất cả Alert.

Ví dụ:

```yaml
osint:
  enabled: true

  policies:
    suspicious_login:
      enabled: true
      entities:
        - username
        - email

    phishing:
      enabled: true
      entities:
        - email
        - username

    malware:
      enabled: false

  limits:
    max_concurrent_scans: 5
    timeout_seconds: 120
    max_retries: 2

  cache:
    username_ttl_seconds: 86400
    email_ttl_seconds: 86400
```

Policy cần kiểm soát:

- Alert type.
- Entity type.
- Severity.
- Tenant.
- Manual/automatic trigger.
- Rate limit.
- Maximum pivot depth.
- Timeout.
- Cache TTL.

---

# 7. Kafka Design

## 7.1. Request topic

```text
osint.enrichment.request
```

Message:

```json
{
  "request_id": "req-uuid",
  "tenant_id": "tenant-123",
  "alert_id": "alert-123",
  "entity": {
    "type": "username",
    "value": "admin-company"
  },
  "scanner": {
    "name": "user-scanner",
    "version": "x.y.z"
  },
  "options": {
    "cross_scan": false,
    "cross_depth": 0
  },
  "requested_at": "2026-08-28T04:00:00Z"
}
```

## 7.2. Result topic

```text
osint.enrichment.result
```

Message:

```json
{
  "request_id": "req-uuid",
  "tenant_id": "tenant-123",
  "alert_id": "alert-123",
  "status": "completed",
  "entity": {
    "type": "username",
    "value": "admin-company"
  },
  "results": [],
  "started_at": "2026-08-28T04:00:00Z",
  "completed_at": "2026-08-28T04:01:20Z"
}
```

Status:

```text
queued
running
completed
partial
failed
timeout
```

## 7.3. Dead Letter Topic

```text
osint.enrichment.dlq
```

Dùng cho:

- malformed request
- scanner crash
- repeated failure
- invalid result
- unsupported entity

---

# 8. OSINT Worker

Worker chịu trách nhiệm:

```text
Kafka Consumer
      ↓
Validate Request
      ↓
Check Cache
      ↓
Run user-scanner
      ↓
Capture stdout/result
      ↓
Validate
      ↓
Normalize
      ↓
Persist
      ↓
Publish result
```

Không để worker phụ thuộc vào database của SIEM Core nếu không cần thiết.

Worker cần có:

- concurrency limit
- timeout
- retry
- cancellation
- structured logging
- metrics
- health check
- graceful shutdown

---

# 9. Cách chạy `user-scanner`

Ưu tiên đóng gói scanner thành container riêng:

```text
osint-worker
    |
    +--> user-scanner container/process
```

Không cài scanner trực tiếp lên host SIEM production.

Ví dụ:

```text
Docker
├── siem-api
├── siem-worker
├── kafka
├── redis
├── opensearch
└── osint-worker
       └── user-scanner
```

Worker phải pin version của scanner để tránh kết quả thay đổi ngoài kiểm soát.

---

# 10. Normalize Result

Không đưa output raw của scanner trực tiếp vào OpenSearch.

Tạo internal schema:

```json
{
  "id": "evidence-uuid",

  "tenant_id": "tenant-123",

  "source": {
    "scanner": "user-scanner",
    "version": "x.y.z"
  },

  "target": {
    "type": "username",
    "value": "admin-company"
  },

  "observation": {
    "platform": "github",
    "found": true,
    "profile_url": "https://example.com/profile",
    "metadata": {}
  },

  "confidence": 0.65,

  "observed_at": "2026-08-28T04:01:00Z"
}
```

---

# 11. Observation vs Identity

Đây là rule bắt buộc.

Không coi:

```text
GitHub: john123
Reddit: john123
```

là:

```text
same_person = true
```

Thay vào đó:

```text
Observation
    |
    +-- platform = github
    +-- username = john123
    +-- evidence = ...
```

và nếu có nhiều evidence:

```text
Identity Candidate
    |
    +-- observations[]
    +-- confidence
```

Chỉ nâng confidence khi có nhiều thuộc tính hỗ trợ:

```text
same username
same email
same avatar
same website
same profile link
same metadata
```

Không dùng username giống nhau làm bằng chứng duy nhất.

---

# 12. Database Model

Có thể bắt đầu với 3 collection/table.

## `osint_enrichment_jobs`

```text
id
tenant_id
alert_id
request_id
entity_type
entity_value
status
scanner
started_at
completed_at
error
created_at
```

## `osint_observations`

```text
id
tenant_id
job_id
entity_type
entity_value
platform
profile_url
metadata
confidence
observed_at
created_at
```

## `osint_evidence`

```text
id
tenant_id
job_id
observation_id
evidence_type
value
source
raw_reference
created_at
```

Raw scanner output có thể lưu riêng và có retention phù hợp, thay vì nhồi toàn bộ vào document chính.

---

# 13. Redis Cache

Key:

```text
osint:username:<normalized-value>
osint:email:<normalized-value>
```

Value:

```json
{
  "status": "completed",
  "result_id": "result-123",
  "scanner_version": "x.y.z",
  "cached_at": "2026-08-28T04:00:00Z"
}
```

Flow:

```text
Request
   ↓
Redis
 ┌─┴─┐
HIT MISS
 │    │
 │    ▼
 │  Scanner
 │    │
 └────┴──> Result
```

Cần normalize input trước khi cache:

```text
John@Example.com
john@example.com
```

phải có cùng canonical key nếu policy của hệ thống coi chúng tương đương.

---

# 14. Correlation với Alert

OSINT result phải tham chiếu ngược về Alert:

```text
Alert
  |
  +-- alert_id
       |
       +-- OSINT Job
              |
              +-- Observations
              |
              +-- Evidence
```

Ví dụ:

```text
Alert #A123
  |
  ├── username: admin-company
  |
  └── OSINT
       ├── GitHub found
       ├── Reddit found
       └── Instagram found
```

---

# 15. Risk / Confidence

Không thay đổi severity gốc của Alert trực tiếp.

Nên có:

```json
{
  "original_severity": "medium",
  "osint": {
    "confidence": 0.78,
    "risk_contribution": 20
  },
  "correlated_risk": 70
}
```

Tách:

```text
Detection Severity
```

và:

```text
OSINT Confidence
```

và:

```text
Correlated Risk
```

để tránh làm mất ngữ nghĩa của detection ban đầu.

---

# 16. OCSF Integration

SIEM hiện tại đã có mapping:

```text
Alert
  ↓
OCSF 2004 Detection Finding

Case
  ↓
OCSF 2005 Incident Finding
```

Giữ nguyên mapper hiện tại.

Thêm OSINT data vào internal finding trước khi export:

```text
Alert
  +
OSINT Evidence
  ↓
Enriched Alert
  ↓
mapAlertToDetectionFinding()
  ↓
OCSF 2004
```

Mapper vẫn phải:

- pure
- không DB side effect
- không gọi Kafka
- không gọi scanner

OSINT service chỉ tạo/enrich domain data; OCSF mapper chỉ chịu trách nhiệm transformation.

OCSF version tiếp tục pin theo version hiện tại của project: `1.1.0`.

---

# 17. API

## Manual scan

```http
POST /api/osint/enrichments
```

Request:

```json
{
  "entity": {
    "type": "username",
    "value": "admin-company"
  }
}
```

Response:

```json
{
  "job_id": "job-123",
  "status": "queued"
}
```

## Get job

```http
GET /api/osint/enrichments/:jobId
```

## Get evidence của Alert

```http
GET /api/alerts/:alertId/osint
```

## Trigger lại

```http
POST /api/osint/enrichments/:jobId/retry
```

Không cho API đồng bộ chờ scanner chạy xong.

---

# 18. UI

Trong Alert Detail thêm:

```text
Alert
├── Overview
├── Events
├── Timeline
├── MITRE ATT&CK
├── Related Alerts
└── OSINT Enrichment
```

OSINT tab:

```text
Target
admin-company

Status
Completed

Platforms
✓ GitHub
✓ Reddit
✓ Instagram
✗ LinkedIn

Observations
3

Confidence
0.72

Scanner
user-scanner x.y.z

Last scanned
...
```

Có nút:

```text
[Run OSINT Scan]
```

và:

```text
[View Evidence]
```

---

# 19. Multi-tenant

Vì SIEM hiện tại có multi-tenant isolation, OSINT data bắt buộc có:

```text
tenant_id
```

ở tất cả domain object:

```text
OSINT Job
Observation
Evidence
Finding
Cache namespace nếu cần
```

Không được để:

```text
tenant A
    ↓
scan
    ↓
result
    ↓
tenant B đọc được
```

Redis cũng phải tránh collision giữa tenant:

```text
osint:<tenant_id>:username:<hash>
```

Nếu kết quả OSINT có thể được chia sẻ giữa tenant, phải thiết kế explicit shared/global cache; mặc định nên coi dữ liệu là tenant-scoped.

---

# 20. Security Requirements

## Secrets

Proxy/API credentials nếu scanner cần phải nằm trong:

```text
Secret Manager / environment secret
```

Không commit vào repository.

## SSRF

Scanner có thể truy cập nhiều URL bên ngoài. Worker phải được cô lập mạng phù hợp.

## Egress

Chỉ cho phép OSINT worker outbound Internet theo policy.

## Rate limit

Có rate limit ở:

```text
API
Kafka consumer
Worker
Per-platform
Per-tenant
```

## Audit

Mọi manual scan cần audit:

```text
who
when
tenant
target
reason
result
```

---

# 21. Observability

Metrics cần có:

```text
osint_scan_requests_total
osint_scan_success_total
osint_scan_failure_total
osint_scan_timeout_total

osint_scan_duration_seconds

osint_cache_hit_total
osint_cache_miss_total

osint_observations_total

osint_queue_lag
osint_worker_active_jobs
```

Dashboard:

```text
OSINT Enrichment
├── Requests/min
├── Success rate
├── Failure rate
├── Average scan duration
├── Queue lag
├── Cache hit ratio
├── Findings by platform
└── Findings by tenant
```

---

# 22. Logging

Mỗi scan phải có correlation ID:

```text
correlation_id
request_id
tenant_id
alert_id
job_id
```

Ví dụ:

```text
[OSINT]
request_id=req-123
tenant=tenant-01
alert=alert-456
entity=username:admin-company
status=completed
duration=42s
```

Không log:

- credential
- proxy password
- sensitive raw response không cần thiết

---

# 23. Retry Strategy

Không retry vô hạn.

Ví dụ:

```text
Attempt 1
   ↓ fail
wait 5s
   ↓
Attempt 2
   ↓ fail
wait 30s
   ↓
Attempt 3
   ↓ fail
DLQ
```

Phân biệt:

```text
retryable
├── timeout
├── temporary network error
└── 5xx

non-retryable
├── invalid request
├── unsupported entity
└── invalid configuration
```

---

# 24. Testing Plan

## Unit

Test:

- entity normalization
- policy matching
- cache key
- result normalization
- confidence calculation
- OCSF mapping

## Integration

Test:

```text
Kafka
 ↓
OSINT Worker
 ↓
user-scanner
 ↓
Kafka result
 ↓
SIEM
```

## Failure tests

Test:

- scanner timeout
- scanner process crash
- malformed JSON
- Kafka unavailable
- Redis unavailable
- OpenSearch unavailable
- duplicate message
- duplicate scan
- tenant isolation

## Security tests

- SSRF
- command injection
- path injection
- secret leakage
- unauthorized tenant access
- rate-limit bypass

---

# 25. Idempotency

Kafka có thể deliver message nhiều lần.

Không được:

```text
message duplicated
    ↓
scan duplicated
    ↓
duplicate findings
```

Dùng:

```text
request_id
```

và unique constraint/idempotency record.

Ví dụ:

```text
tenant_id
+
entity_type
+
normalized_entity
+
scanner_version
+
policy_version
```

có thể dùng để xác định cache/dedup tùy nghiệp vụ.

---

# 26. Implementation Phases

## Phase 0 — Repository & spike

- [ ] Fork/pin `user-scanner`.
- [ ] Đọc CLI/API/output format hiện tại.
- [ ] Xác định cách chạy ổn định trong container.
- [ ] Xác định JSON output cần consume.
- [ ] Xác định timeout/concurrency.
- [ ] Kiểm tra license và dependency.
- [ ] Tạo proof-of-concept scan một username/email.

Deliverable:

```text
user-scanner → machine-readable result
```

---

## Phase 1 — OSINT Worker

- [ ] Tạo `osint-worker`.
- [ ] Kafka consumer.
- [ ] Request validation.
- [ ] Scanner adapter.
- [ ] Timeout.
- [ ] Retry.
- [ ] Structured logging.
- [ ] Health check.
- [ ] Docker image.

Deliverable:

```text
Kafka request
    ↓
worker
    ↓
user-scanner
    ↓
Kafka result
```

---

## Phase 2 — SIEM Integration

- [ ] Entity extraction.
- [ ] Enrichment policy.
- [ ] Publish `osint.enrichment.request`.
- [ ] Consume result.
- [ ] Persist job/result.
- [ ] Link result với Alert.

Deliverable:

```text
Alert → OSINT → Alert enrichment
```

---

## Phase 3 — Redis + Reliability

- [ ] Redis cache.
- [ ] Idempotency.
- [ ] Deduplication.
- [ ] DLQ.
- [ ] Backoff.
- [ ] Rate limit.
- [ ] Tenant-aware cache.

Deliverable:

```text
Reliable OSINT enrichment pipeline
```

---

## Phase 4 — Correlation

- [ ] Observation model.
- [ ] Evidence model.
- [ ] Confidence model.
- [ ] Correlation rules.
- [ ] Risk contribution.
- [ ] Related entity detection.

Deliverable:

```text
Alert
 +
OSINT Evidence
 ↓
Correlated Risk
```

---

## Phase 5 — OCSF

- [ ] Extend domain model để chứa OSINT enrichment.
- [ ] Giữ nguyên pure OCSF mapper.
- [ ] Map enriched Alert → OCSF 2004.
- [ ] Map related Case → OCSF 2005.
- [ ] Test OCSF 1.1.0 output.

Deliverable:

```text
OSINT-enriched Alert
        ↓
OCSF 1.1.0
```

---

## Phase 6 — UI

- [ ] OSINT tab trong Alert Detail.
- [ ] Manual scan.
- [ ] Job status.
- [ ] Platform results.
- [ ] Evidence.
- [ ] Confidence.
- [ ] Scan history.
- [ ] Audit information.

Deliverable:

```text
Alert → OSINT → Evidence
```

---

## Phase 7 — Observability & Production Hardening

- [ ] Metrics.
- [ ] Dashboard.
- [ ] Alerting.
- [ ] Worker autoscaling.
- [ ] Egress policy.
- [ ] Resource limits.
- [ ] Security review.
- [ ] Load test.
- [ ] Failure injection.
- [ ] Documentation.

---

# 27. Definition of Done cho MVP

MVP được coi là hoàn thành khi:

- [ ] Một Alert có username/email có thể trigger OSINT enrichment.
- [ ] Request được đưa qua Kafka.
- [ ] Worker chạy `user-scanner`.
- [ ] Worker trả machine-readable result.
- [ ] Result được normalize.
- [ ] Result được lưu với `tenant_id`.
- [ ] Alert có thể xem OSINT evidence.
- [ ] Duplicate request không tạo duplicate scan/finding ngoài policy.
- [ ] Timeout/failure không làm SIEM Core ảnh hưởng.
- [ ] Có retry + DLQ.
- [ ] Có Redis cache.
- [ ] Có audit log.
- [ ] Có metrics.
- [ ] Có tenant isolation.
- [ ] OCSF mapper hiện tại không bị phá vỡ.
- [ ] Có test cho happy path và failure path.

---

# 28. Demo flow đề xuất

Dùng một Alert giả lập:

```text
Suspicious Login
username = suspicious_user
email = attacker@example.com
```

Flow demo:

```text
1. Generate suspicious login
          ↓
2. SIEM Detection Engine
          ↓
3. Alert created
          ↓
4. Entity Extractor
          ↓
5. username/email detected
          ↓
6. Enrichment Policy = allowed
          ↓
7. Kafka request
          ↓
8. OSINT Worker
          ↓
9. user-scanner
          ↓
10. Results normalized
          ↓
11. Evidence persisted
          ↓
12. Correlation
          ↓
13. Risk updated
          ↓
14. Alert UI shows OSINT
          ↓
15. Optional OCSF export
```

Đây là flow nên dùng để bảo vệ/demo vì nó thể hiện rõ:

```text
Detection
→ Enrichment
→ Evidence
→ Correlation
→ Risk
→ Finding
→ Investigation
```

---

# 29. Kiến trúc package đề xuất

Nếu backend hiện tại là NestJS:

```text
apps/
├── api/
│   └── src/
│       └── modules/
│           └── osint/
│               ├── osint.controller.ts
│               ├── osint.service.ts
│               ├── osint.policy.ts
│               └── osint.types.ts
│
└── osint-worker/
    └── src/
        ├── consumers/
        │   └── enrichment-request.consumer.ts
        ├── scanners/
        │   ├── scanner.interface.ts
        │   └── user-scanner.adapter.ts
        ├── normalizers/
        │   └── user-scanner.normalizer.ts
        ├── services/
        │   ├── cache.service.ts
        │   └── enrichment.service.ts
        └── metrics/
            └── osint.metrics.ts

libs/
└── core/
    └── osint/
        ├── entities/
        ├── schemas/
        ├── policies/
        └── types/
```

Interface scanner:

```text
Scanner
├── scan()
├── supports()
├── healthCheck()
└── version()
```

Sau này có thể thêm:

```text
UserScanner
VirusTotal
AbuseIPDB
Whois
CertificateTransparency
URLScan
```

mà không sửa OSINT orchestration layer.

---

# 30. End State

Kiến trúc cuối cùng:

```text
                        ┌───────────────┐
                        │     SIEM      │
                        └───────┬───────┘
                                │
                         Detection
                                │
                                ▼
                             Alert
                                │
                                ▼
                       Entity Extraction
                                │
                                ▼
                       Enrichment Policy
                                │
                                ▼
                              Kafka
                                │
              ┌─────────────────┴─────────────────┐
              │                                   │
              ▼                                   ▼
       OSINT Worker                         Other Enrichers
              │
              ▼
       user-scanner
              │
              ▼
         Observations
              │
              ▼
           Evidence
              │
              ▼
         Correlation
              │
              ▼
         Risk / Confidence
              │
              ▼
        Enriched Finding
              │
        ┌─────┴─────┐
        ▼           ▼
   OpenSearch      Case
        │
        ▼
    Dashboard
        │
        ▼
   OCSF Export
```

**Core architectural decision:**

> `user-scanner` = **collection/enrichment adapter**  
> Kafka = **asynchronous transport**  
> Redis = **cache/idempotency layer**  
> OpenSearch = **search/analytics**  
> SIEM Correlation Engine = **decision layer**  
> OCSF = **normalization/export layer**

Không để `user-scanner` quyết định một entity có malicious hay không. Nó chỉ cung cấp **observations/evidence**; quyết định thuộc về detection/correlation/risk layer của SIEM.
