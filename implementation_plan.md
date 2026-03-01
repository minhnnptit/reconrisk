# ReconRisk — Modular Recon CLI (Terminal Prototype)

## Core Concept

Standard recon tools chạy tất cả mọi thứ theo kiểu "hộp đen". **ReconRisk** cho phép bạn chọn đúng phase cần chạy, ở độ sâu cần thiết — và **phát hiện thay đổi bề mặt tấn công** giữa các lần scan. Phù hợp với workflow pentest định kỳ.

```
[Quick check]    python3 recon.py -d target.com --steps subdomain,probe
[Deep dive]      python3 recon.py -d target.com --steps subdomain,port,cve --depth deep
[Full + diff]    python3 recon.py -d target.com --all --compare
```

---

## What Makes This Different

| Feature                   | Standard tools | ReconRisk       |
|---------------------------|----------------|-----------------|
| Chọn phase chạy           | ✗              | ✅ `--steps`    |
| Fast / Deep per phase     | ✗              | ✅ `--depth`    |
| CVE enrichment (NVD API)  | ✗              | ✅              |
| Risk score per host       | ✗              | ✅ 0–100        |
| **Delta so sánh 2 scan**  | ✗              | ✅ `--compare`  |
| Output                    | Log, file      | Terminal table  |

---

## CLI Design

```bash
python3 recon.py [OPTIONS]

Required:
  -d, --domain      Target domain

Scope:
  --steps           Comma-separated: subdomain, probe, port, cve, risk, delta
                    Default: all steps
  --all             Shorthand: chạy tất cả phase

Depth:
  --depth           fast | deep  (default: fast)

  fast:  subfinder + assetfinder  |  top 100 ports  |  CVE từ server header
  deep:  subfinder wordlist lớn   |  top 1000 ports  |  CVE từ service version đầy đủ

Delta:
  --compare         So sánh với lần scan trước (baseline.json)
                    Lần đầu: tự động lưu baseline
                    Lần sau: in diff (NEW / GONE / CHANGED)

Output:
  -o, --output      Thư mục lưu kết quả (default: ./results/<domain>/)
  --top N           Chỉ hiện top-N host rủi ro nhất trên terminal

Misc:
  --threads         Concurrency (default: 10)
  --timeout         Timeout mỗi phase (seconds, default: 120)
  --no-cache        Tắt CVE cache
  --nvd-key         NVD API key (optional, tăng rate limit)
```

### Usage Examples

```bash
# Chỉ enum subdomain
python3 recon.py -d example.com --steps subdomain

# Subdomain → alive check → risk score
python3 recon.py -d example.com --steps subdomain,probe,risk

# Full scan, deep mode, top 10 rủi ro nhất
python3 recon.py -d example.com --all --depth deep --top 10

# Full scan + so sánh với lần scan trước
python3 recon.py -d example.com --all --compare

# Skip thẳng vào CVE + risk (biết host rồi)
python3 recon.py -d example.com --steps cve,risk --depth deep
```

---

## Prerequisites & Environment (Linux)

```bash
# Ubuntu/Debian system deps
sudo apt-get install -y nmap python3 python3-pip golang-go

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/assetfinder@latest

# Thêm Go bin vào PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Python deps
pip3 install -r requirements.txt
```

> [!NOTE]
> `amass` bị loại khỏi prototype vì cài nặng và chậm. `--depth deep` dùng subfinder với wordlist lớn hơn thay thế.

---

## File Structure

```
reconrisk/
├── recon.py                ← CLI entry point (argparse + pipeline)
├── requirements.txt        ← rich, requests, dnspython
├── setup.sh                ← Script tự động cài Go tools (Linux)
├── README.md
├── modules/
│   ├── __init__.py         ← Phase registry: PHASES list
│   ├── subdomain.py        ← subfinder + assetfinder (subprocess)
│   ├── http_probe.py       ← httpx subprocess + requests fallback
│   ├── port_scan.py        ← nmap -oX stdout, parse xml.etree
│   ├── cve_lookup.py       ← NVD API v2 + disk cache JSON
│   ├── risk_score.py       ← pure function, no I/O
│   ├── delta.py            ← baseline load/save/diff
│   └── report.py           ← rich table + JSON dump
└── results/
    └── <domain>/
        ├── subdomains.txt
        ├── report.json
        └── baseline.json
```

---

## Phase Details

### Phase 1 — Subdomain Enum (`subdomain`)

| Mode   | Tools                            | ~Time    |
|--------|----------------------------------|----------|
| `fast` | subfinder + assetfinder          | 15–30s   |
| `deep` | subfinder với wordlist lớn hơn   | 1–2 min  |

- Chạy bằng `subprocess.run()`, deduplicate output
- Fallback: `dnspython` brute resolve nếu thiếu subfinder
- Output: `subdomains.txt`

---

### Phase 2 — HTTP Probe (`probe`)

| Mode   | What it does                                     |
|--------|--------------------------------------------------|
| `fast` | httpx: status code, title, server header         |
| `deep` | + follow redirects, HTTPS check, tech headers    |

- Gọi `httpx -l subdomains.txt -silent -sc -title -server -json`
- Parse JSON output từng dòng
- Fallback: `requests.get()` với timeout nếu thiếu httpx
- Output: list dict `{url, status, title, server}`

---

### Phase 3 — Port Scan (`port`)

| Mode   | nmap flags                    | ~Time     |
|--------|-------------------------------|-----------|
| `fast` | `-T4 --top-ports 100 -sV`     | 2–5 min   |
| `deep` | `-T4 --top-ports 1000 -sV -O` | 5–15 min  |

- Gọi `nmap -oX -` (XML output to stdout)
- Parse bằng `xml.etree.ElementTree` (stdlib, không cần dep thêm)
- Output: `{ip: {ports, services, os_guess}}`

---

### Phase 4 — CVE Enrichment (`cve`) ⭐

| Mode   | Source                                            |
|--------|---------------------------------------------------|
| `fast` | Server header từ probe phase → NVD keyword search |
| `deep` | service:version đầy đủ từ nmap → NVD API v2       |

- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<service+version>`
- Rate limit: sleep 0.6s giữa các request (6s nếu không có API key)
- Cache: `~/.reconrisk/cve_cache.json` (tránh query lại cùng version)
- Optional: `--nvd-key` để tăng rate limit (50 req/30s)

Output per service:
```json
{
  "service": "nginx", "version": "1.18.0",
  "cves": [{"id": "CVE-2021-23017", "cvss": 9.8, "description": "..."}]
}
```

---

### Phase 5 — Risk Score (`risk`) ⭐

Pure computation — không gọi network. Tổng hợp tất cả phase trước, score mỗi host 0–100:

```
Signal                                  Points
CRITICAL CVE (CVSS ≥ 9.0)              +40
HIGH CVE (CVSS 7.0–8.9)                +25
MEDIUM CVE (CVSS 4.0–6.9)              +10 (max +20)
Sensitive ports (22, 3306, 5432...)     +15
Admin/dev ports (8080, 9000...)         +10
HTTP only, no HTTPS                     +10
```

```
Score   Band
≥ 70    CRITICAL 🔴
50–69   HIGH     🟠
30–49   MEDIUM   🟡
< 30    LOW      🟢
```

Signature: `score_host(probe_data, port_data, cve_data) → int`

---

### Phase 6 — Delta / Diff (`delta`) ⭐

So sánh kết quả scan hiện tại với baseline đã lưu từ lần trước.

**Lần đầu chạy `--compare`:** Lưu `results/<domain>/baseline.json`

**Lần tiếp theo:** So sánh và in ra:
```
[NEW]     api.example.com → port 3306 mở  (⚠️ sensitive port)
[GONE]    old.example.com → host đã offline
[CHANGED] www.example.com → CVE-2024-1234 xuất hiện (CVSS 9.1)
[CHANGED] www.example.com → risk score: 35 → 75 (+40)
```

Logic: plain Python `dict diff` — không cần thư viện thêm.

---

### Phase 7 — Terminal Report (`report`)

`rich` colored table, tự động chạy sau bất kỳ phase nào có dữ liệu.

- Columns: Host | Status | Open Ports | Top CVE | Risk Score | Band
- Sorted by risk score (cao → thấp)
- Nếu có `--top N`: chỉ hiện N host rủi ro nhất
- Nếu có `--compare`: thêm section "Changes since last scan"
- Output file: `results/<domain>/report.json`

---

## Graceful Degradation

| External tool | Nếu thiếu |
|---------------|-----------|
| `subfinder`   | Dùng `dnspython` brute resolve nhẹ |
| `assetfinder` | Skip silently, subfinder đủ |
| `httpx`       | Fallback sang `requests.get()` |
| `nmap`        | Skip port phase, warn user |
| `amass`       | Loại khỏi prototype hoàn toàn |
| NVD API       | Timeout/error → log warning, scoring với 0 CVEs |

> [!NOTE]
> Mọi subprocess call đều có `try/except FileNotFoundError` để graceful skip.

---

## requirements.txt

```
rich>=13.0
requests>=2.28
dnspython>=2.3
```

---

## Timeline (3 ngày)

| Ngày      | Focus                                                          |
|-----------|----------------------------------------------------------------|
| **Day 1** | scaffold + `recon.py` CLI + Phase 1 (subdomain) + Phase 2 (probe) |
| **Day 2** | Phase 3 (port) + Phase 4 (CVE + cache) + Phase 5 (risk)       |
| **Day 3** | Phase 6 (delta/diff) + Phase 7 (report) + `setup.sh` + README |

---

## Verification Commands (Linux)

```bash
# Cài Python deps
pip3 install -r requirements.txt

# Test 1: Chỉ subdomain + probe (không cần nmap/NVD)
python3 recon.py -d scanme.nmap.org --steps subdomain,probe

# Test 2: Full scan fast mode
python3 recon.py -d scanme.nmap.org --all --depth fast

# Test 3: Delta — chạy lần 1 (tạo baseline)
python3 recon.py -d scanme.nmap.org --all --compare

# Test 4: Delta — chạy lần 2 (thấy diff)
python3 recon.py -d scanme.nmap.org --all --compare

# Expected files sau Test 4:
# results/scanme.nmap.org/subdomains.txt
# results/scanme.nmap.org/report.json
# results/scanme.nmap.org/baseline.json
# Terminal: rich colored table + "Changes since last scan" section
```
