# ReconRisk v2 — Phase Reference Guide

Tài liệu chi tiết từng phase: mục đích, tools, tiêu chí lọc, output.

---

## Tổng quan Pipeline

```
subdomain → resolve → prioritize → [PAUSE 1] → probe → [PAUSE 2]
→ techdetect → port → [PAUSE 3] → fuzz → cve → paramfind
→ risk → delta → report
```

### CLI Options

| Option | Mặc định | Mô tả |
|--------|----------|-------|
| `-d DOMAIN` | (bắt buộc) | Domain mục tiêu |
| `--all` | off | Chạy tất cả 12 phases |
| `--steps p1,p2,...` | all | Chọn phases cụ thể |
| `--depth fast\|deep` | fast | Mức độ quét |
| `-i, --interactive` | off | Cho phép chọn target tại 3 điểm pause |
| `--compare` | off | So sánh với lần scan trước |
| `--top N` | unlimited | Chỉ hiện top N hosts riskiest |
| `--timeout N` | 120s | Timeout mỗi phase |
| `--threads N` | 10 | Số luồng song song |
| `--no-cache` | off | Bỏ qua CVE cache |
| `--nvd-key KEY` | none | NVD API key (nhanh hơn 10x) |

---

## Phase 1: `subdomain` — Subdomain Enumeration

### Mục đích
Thu thập tất cả subdomain của target domain từ nhiều nguồn.

### Tools & Sources

| Source | Mode | Phương pháp | Fallback |
|--------|------|-------------|----------|
| subfinder | fast + deep | OSINT passive enum | skip nếu không có |
| assetfinder | fast + deep | OSINT passive enum | skip nếu không có |
| crt.sh | fast + deep | Certificate Transparency logs | luôn available |
| amass | deep only | Passive enum (chậm) | skip nếu không có |
| DNS bruteforce | fallback | 53 prefixes × dnspython | chỉ khi không có tool nào |

### Tiêu chí lọc crt.sh
- Loại bỏ wildcard (`*.example.com`)
- Loại bỏ garbage subdomain (`xxx.comwww.domain.com`)
- Validate: chỉ chứa a-z, 0-9, hyphen, dots
- Reject labels > 63 chars hoặc chứa `.com` mid-string

### Output
- `results/<domain>/subdomains.txt` — danh sách subdomain (1 per line)
- Return: `list[str]`

### Fast vs Deep
| | Fast | Deep |
|--|------|------|
| subfinder | default mode | `--all --recursive` |
| amass | skip | passive enum |
| Thời gian | ~30s | ~2-5 phút |

---

## Phase 2: `resolve` — DNS Resolution

### Mục đích
Resolve mỗi subdomain → IP addresses, detect CNAME cho subdomain takeover.

### Logic
1. Resolve A records (IPv4)
2. Resolve AAAA records (IPv6)
3. Check CNAME records → potential subdomain takeover
4. **Retry 3 lần** với timeout tăng dần: 5s → 10s → 15s
5. **Socket fallback**: nếu dnspython fail, dùng `socket.getaddrinfo()`
6. Luôn đảm bảo root domain được include

### Subdomain Takeover Detection
Kiểm tra CNAME trỏ đến dịch vụ có thể bị claim:

| Service | CNAME Pattern |
|---------|--------------|
| GitHub Pages | `*.github.io` |
| Heroku | `*.herokuapp.com` |
| AWS S3 | `*.s3.amazonaws.com` |
| Shopify | `*.myshopify.com` |
| Azure | `*.azurewebsites.net` |
| Fastly | `*.fastly.net` |
| Pantheon | `*.pantheonsite.io` |
| Tumblr | `*.tumblr.com` |

### Output
- `results/<domain>/dns_map.json`
- Return: `dict` với `hosts`, `ip_map`, `unique_ips`, `takeovers`

---

## Phase 3: `prioritize` — Subdomain Scoring

### Mục đích
Gán điểm 0-100 cho mỗi subdomain, ưu tiên targets có attack surface lớn nhất.

### 🎯 PAUSE 1 (`-i`): User chọn subdomain sau phase này

### Tiêu chí scoring

#### Positive (tăng điểm)

| Signal | Điểm | Giải thích |
|--------|-------|-----------|
| High-value prefix (`admin`, `dev`, `api`, `staging`, `vpn`, `sso`, `auth`) | +35 | Environments thường có security yếu hơn |
| High-value trong deep sub (`dev.api.example.com`) | +30 | Bất kỳ level nào chứa prefix thú vị |
| Non-prod prefix (`test`, `beta`, `sandbox`, `demo`, `debug`) | +20 | Có thể có debug features |
| Infra prefix (`jenkins`, `gitlab`, `redis`, `grafana`, `k8s`) | +15 | Potential misconfigurations |
| Subdomain takeover (CNAME → dịch vụ bị abandon) | +40 | Vulnerability trực tiếp |
| External CNAME (CNAME trỏ ngoài domain) | +20 | Takeover potential |
| Internal CNAME (CNAME trong cùng domain) | +5 | Ít rủi ro hơn |
| Unique IP (chỉ 1 subdomain dùng) | +15 | Có thể là server riêng |
| Rare IP (≤3 subdomains dùng chung) | +5 | Ít common hơn |
| Internal IP (`10.x`, `192.168.x`, `172.16-31.x`) | +20 | Internal infrastructure exposure |
| Deep + interesting prefix | +15 | `admin.dev.api.example.com` |
| Deep generic | +3 | Depth alone không = thú vị |
| Resolved | +5 | Baseline score |

#### Negative (giảm điểm)

| Signal | Điểm | Giải thích |
|--------|-------|-----------|
| Low-value prefix (`cdn`, `static`, `img`, `assets`, `fonts`) | -10 | Static content, ít attack surface |
| S3/storage prefix (`s3`, `storage`, `bucket`) | -10 | Object storage |
| Marketing/tracking (`ads`, `tracking`, `analytics`, `pixel`) | -10 | Third-party, not our scope |
| Public-facing (`www`, `blog`, `shop`, `store`) | -10 | Hardened, WAF protected |
| Numeric subdomain (`1`, `2`, `1.3`) | -15 | Thường là auto-generated |
| Garbage pattern (`comwww`, `_dmarc`) | -15 | DNS records, not hosts |

#### Filter (loại bỏ hoàn toàn)

| Điều kiện | Hành động |
|-----------|-----------|
| Không resolve được (dead) | Loại bỏ |
| Score ≤ 0 | Loại bỏ (quá thấp) |
| Wildcard IP + score < 25 | Loại bỏ |
| **Root domain** | **Luôn giữ** (min score = 15) |

### Wildcard DNS Detection
- Nếu >50% resolved subdomains trỏ cùng 1 IP → wildcard
- Nếu >20 subdomains trỏ cùng 1 IP → wildcard
- Wildcard subdomains bị filter trừ khi score ≥ 25

### Interactive Selection (`-i`)

| Input | Ý nghĩa |
|-------|---------|
| `all` | Chọn tất cả (Enter mặc định) |
| `1-5,8,12` | Chọn theo số thứ tự |
| `high-value` | Chọn theo tag |
| `top 10` | Chọn top N score cao nhất |

---

## Phase 4: `probe` — HTTP Probing

### Mục đích
Kiểm tra subdomain nào thật sự alive (respond HTTP/HTTPS).

### 🌐 PAUSE 2 (`-i`): User chọn alive hosts sau phase này

### Tools

| Tool | Ưu tiên | Cách tìm |
|------|---------|----------|
| httpx (Go binary) | 1 | `~/go/bin/httpx` → `GOPATH/bin` → PATH |
| requests (Python) | 2 | Fallback, chạy qua ThreadPool |

### Output cho mỗi host
- `status` — HTTP status code
- `url` — Final URL (after redirect)
- `title` — Page title
- `server` — Server header
- `tls.enabled` — HTTPS?
- `content_length` — Response size

### Tiêu chí hiển thị
Tất cả hosts trả response đều hiện, bao gồm 503/5xx.

---

## Phase 5: `techdetect` — Technology Detection

### Mục đích
Xác định tech stack của web hosts: CMS, framework, language, server.

### Methods (theo thứ tự)

| Method | Detects | Ví dụ |
|--------|---------|-------|
| whatweb (subprocess) | CMS, framework, server | WordPress, Drupal, Apache |
| HTTP headers analysis | Server software, language | `Server: nginx`, `X-Powered-By: PHP` |
| HTML body patterns | Frontend frameworks, CMS | `/wp-content/` → WordPress |

### Header patterns

| Header | Pattern | Detect |
|--------|---------|--------|
| `Server` | `Apache`, `nginx`, `IIS` | Web server |
| `X-Powered-By` | `PHP`, `ASP.NET`, `Express` | Backend language |
| `Set-Cookie` | `PHPSESSID`, `JSESSIONID` | PHP, Java |
| `X-Generator` | `WordPress`, `Drupal` | CMS |

### Body patterns

| Pattern | Technology |
|---------|-----------|
| `/wp-content/` | WordPress |
| `__NEXT_DATA__` | Next.js |
| `ng-version` | Angular |
| `__nuxt` | Nuxt.js |
| `react-root`, `_reactRootContainer` | React |

---

## Phase 6: `port` — Port Scanning

### Mục đích
Quét open ports và identify services trên IP targets.

### 🔍 PAUSE 3 (`-i`): User chọn hosts theo port/service sau phase này

### Targets
- **Ưu tiên**: Unique IPs từ resolve phase (tránh scan trùng)
- **Fallback**: Subdomains trực tiếp
- **Giới hạn**: Max 50 hosts

### Fast vs Deep

| | Fast | Deep |
|--|------|------|
| Ports | Top 100 | Top 1000 |
| Version detect | `-sV` | `-sV -O` (+ OS detect) |
| Timing | `-T4` | `-T4` |
| Thời gian | ~30s | ~2-5 phút |

### Output cho mỗi host
- `ports[]` — list of `{port, protocol, state, service, version}`
- `os` — OS detection (deep mode)
- `ip` — Target IP

---

## Phase 7: `fuzz` — Web Directory Fuzzing

### Mục đích
Tìm hidden directories, files, admin panels, config leaks.

### Host filtering
- **Chỉ fuzz**: hosts có status 200, 201, 301, 302, 307, 401, 403
- **Skip**: 503, 5xx, timeout
- **Giới hạn**: fast = 20 hosts, deep = 50 hosts
- **Timeout**: max 60s per host

### Wordlist

| Depth | Wordlist | Entries |
|-------|----------|---------|
| fast | `wordlists/dirs_small.txt` | ~120 paths |
| deep | SecLists `common.txt` hoặc `dirs_large.txt` | ~4600 paths |

### Auto-flag categories

| Category | Pattern | Risk | Emoji |
|----------|---------|------|-------|
| Admin Panel | `/admin`, `/dashboard`, `/wp-admin` | +10 | 🔴 |
| Config Leak | `/.git`, `/.env`, `/.htaccess`, `/phpinfo` | +20 | 🔴 |
| Backup File | `.bak`, `.sql`, `.zip`, `.tar.gz` | +15 | 🔴 |
| API Endpoint | `/api`, `/graphql`, `/swagger` | +5 | 🟠 |
| Info Disclosure | `/server-status`, `/debug`, `/health` | +10 | 🟠 |
| File Upload | `/upload`, `/media` | +5 | 🟡 |

---

## Phase 8: `cve` — CVE Lookup

### Mục đích
Tra cứu CVE cho mỗi service/technology phát hiện được.

### Sources
1. Port scan services (Apache 2.4.7, OpenSSH 6.6.1p1)
2. Tech detect results (WordPress, Drupal)

### NVD API v2
- Query: `keywordSearch` = service + version
- Limit: 50 results per query
- Filter: CVSS ≥ 4.0
- Cache: `~/.reconrisk/cve_cache.json` (avoid re-querying)

### Rate limiting

| Có API key | Không có key |
|------------|-------------|
| 0.6s giữa mỗi request | 6s giữa mỗi request |

### Severity classification (tính từ CVSS score)

| CVSS | Severity |
|------|----------|
| ≥ 9.0 | 🔴 CRITICAL |
| 7.0 - 8.9 | 🟠 HIGH |
| 4.0 - 6.9 | 🟡 MEDIUM |

### Deduplication
CVE trùng ID + cùng host chỉ hiện 1 lần.

---

## Phase 9: `paramfind` — Parameter Discovery

### Mục đích
Tìm hidden GET/POST parameters trên web hosts.

### Host filtering
- **Chỉ scan**: hosts có status 200, 201, 301, 302, 307, 401, 403
- **Giới hạn**: fast = 10 hosts, deep = 25 hosts
- **Timeout**: fast = 60s/host, deep = 90s/host

### Tool
- arjun (subprocess) → output JSON file
- Loại bỏ ANSI codes, banner text từ output

### Auto-flag dangerous parameters

| Category | Patterns | Attack Type | Risk |
|----------|----------|------------|------|
| SSRF/Redirect | `url`, `redirect`, `next`, `callback` | SSRF, Open Redirect | 🔴 +15 |
| LFI/RFI | `file`, `path`, `page`, `include`, `template` | File Inclusion | 🔴 +15 |
| RCE | `cmd`, `exec`, `command`, `shell` | Remote Code Execution | 🔴 +20 |
| IDOR | `id`, `uid`, `user_id`, `account` | Insecure Direct Object Ref | 🟠 +10 |
| SQLi/XSS | `q`, `search`, `query`, `comment` | SQL Injection, XSS | 🟠 +10 |
| Debug/Admin | `debug`, `test`, `admin`, `mode` | Hidden Debug Features | 🟠 +10 |
| SSTI | `template`, `render`, `tpl` | Server-Side Template Injection | 🟡 +10 |

---

## Phase 10: `risk` — Risk Scoring

### Mục đích
Tính risk score 0-100 cho mỗi host, tổng hợp từ tất cả phases.

### Scoring table

| Signal | Điểm | Source |
|--------|-------|--------|
| CRITICAL CVE (CVSS ≥ 9.0) | +40 | cve phase |
| HIGH CVE (CVSS 7.0-8.9) | +25 | cve phase |
| MEDIUM CVE (CVSS 4.0-6.9) | +10 (max 20) | cve phase |
| Subdomain takeover | +40 | resolve phase |
| Config leak (.git, .env) | +20 | fuzz phase |
| Sensitive ports (22, 3306, 5432, 6379...) | +15 | port phase |
| Dangerous params (SSRF/LFI/RCE) | +15 | paramfind phase |
| Backup files found | +15 | fuzz phase |
| Admin ports (8080, 9000...) | +10 | port phase |
| Admin panel found | +10 | fuzz phase |
| Debug params | +10 | paramfind phase |
| HTTP only (no HTTPS) | +10 | probe phase |

### Risk bands

| Score | Band | Ý nghĩa |
|-------|------|---------|
| ≥ 70 | 🔴 CRITICAL | Có CVE critical hoặc nhiều signals |
| 50-69 | 🟠 HIGH | Nhiều CVE + exposed services |
| 30-49 | 🟡 MEDIUM | Một số findings |
| < 30 | 🟢 LOW | Ít attack surface |

---

## Phase 11: `delta` — Baseline Comparison

### Mục đích
So sánh scan hiện tại với lần scan trước, phát hiện thay đổi.

### Yêu cầu
- `--compare` flag
- Lần scan đầu tiên → lưu làm baseline
- Lần scan tiếp theo → so sánh với baseline

### Change types

| Tag | Ý nghĩa |
|-----|---------|
| `[NEW]` | Host/port/CVE mới xuất hiện |
| `[GONE]` | Host/port đã offline |
| `[CHANGED]` | Risk score thay đổi |

### Storage
- `results/<domain>/baseline.json`

---

## Phase 12: `report` — Report Generation

### Mục đích
Hiển thị kết quả tổng hợp dưới dạng Rich tables + export JSON.

### Tables hiển thị
1. **Main table**: Host, Status, Open Ports, CVEs, Score, Risk Band
2. **CVE detail table**: Host, CVE ID, CVSS, Severity, Description
3. **Summary panel**: Total hosts, alive count, risk distribution
4. **Delta table** (nếu `--compare`): Changes

### Output
- `results/<domain>/report.json` — full JSON export
- Terminal: Rich formatted tables

---

## Graceful Degradation

Tool nào bị thiếu → tự động fallback hoặc skip:

| Tool | Missing? | Fallback |
|------|----------|----------|
| subfinder | Skip, dùng source khác | crt.sh + assetfinder + DNS brute |
| assetfinder | Skip silently | Các source khác |
| httpx (Go) | Dùng requests | ThreadPool + requests.get |
| nmap | Skip port phase | Warn user |
| ffuf | Dùng requests | Brute-force qua requests |
| arjun | Skip param phase | Warn user |
| whatweb | Skip, dùng headers/body | HTTP header + body analysis |
| amass | Skip (deep only) | Các source khác |
| NVD API | Timeout → 0 CVEs | Cache nếu có |
