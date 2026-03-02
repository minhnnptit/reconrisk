# ReconRisk v2 — Implementation Plan

## Core Concept

Standard recon tools chạy tất cả theo kiểu "hộp đen". **ReconRisk** cho phép:
- **Chọn phase** cần chạy (`--steps`)
- **Chọn độ sâu** per phase (`--depth fast|deep`)
- **Chọn target** tại 3 điểm pause (`-i` interactive mode)
- **Phát hiện thay đổi** bề mặt tấn công giữa các lần scan (`--compare`)

```
[Quick scan]     python3 recon.py -d target.com --all --depth fast
[Deep + select]  python3 recon.py -d target.com --all --depth deep -i
[Delta diff]     python3 recon.py -d target.com --all --compare
```

---

## What Makes This Different

| Feature | Standard tools | ReconRisk |
|---------|---------------|-----------|
| Chọn phase chạy | ✗ | ✅ `--steps` |
| Fast / Deep per phase | ✗ | ✅ `--depth` |
| Interactive target selection | ✗ | ✅ `-i` (3 pause points) |
| CVE enrichment (NVD API) | ✗ | ✅ auto-query |
| Tech stack detection | ✗ | ✅ whatweb + headers |
| Directory fuzzing + auto-flag | ✗ | ✅ admin/config/backup |
| Parameter discovery + danger flags | ✗ | ✅ SSRF/LFI/RCE |
| Risk score per host | ✗ | ✅ 0–100 composite |
| Delta so sánh 2 scan | ✗ | ✅ `--compare` |
| Smart subdomain scoring | ✗ | ✅ 30+ patterns |

---

## Pipeline — 12 Phases

```
subdomain → resolve → prioritize → [PAUSE 1] → probe → [PAUSE 2]
→ techdetect → port → [PAUSE 3] → fuzz → cve → paramfind
→ risk → delta → report
```

| # | Phase | Tool | Fast vs Deep |
|---|-------|------|-------------|
| 1 | subdomain | subfinder + assetfinder + crt.sh + amass | fast: 2 tools / deep: +amass |
| 2 | resolve | dnspython (retry 3x) + socket fallback | Same |
| 3 | prioritize | Scoring engine (v2.1) | Same |
| 4 | probe | httpx (Go) / requests | Same |
| 5 | techdetect | whatweb + header/body analysis | Same |
| 6 | port | nmap | fast: top 100 / deep: top 1000 + OS |
| 7 | fuzz | ffuf / requests | fast: small.txt, 20 hosts / deep: large.txt, 50 hosts |
| 8 | cve | NVD API v2 + cache | Same |
| 9 | paramfind | arjun → temp JSON | fast: 10 hosts / deep: 25 hosts |
| 10 | risk | Pure computation, 0-100 | Same |
| 11 | delta | Baseline diff | Same |
| 12 | report | Rich tables + JSON | Same |

---

## CLI Design

```bash
python3 recon.py [OPTIONS]

Required:
  -d, --domain         Target domain

Scope:
  --all                Run all 12 phases
  --steps p1,p2,...    Chọn phases cụ thể (comma-separated)

Depth:
  --depth fast|deep    Mức độ quét (default: fast)

Interactive:
  -i, --interactive    Pause tại 3 điểm để user chọn targets

Delta:
  --compare            So sánh với lần scan trước (baseline.json)

Output:
  -o, --output         Thư mục lưu kết quả (default: ./results/<domain>/)
  --top N              Chỉ hiện top-N host rủi ro nhất

Performance:
  --threads N          Concurrency (default: 10)
  --timeout N          Timeout mỗi phase (default: 120s)

CVE:
  --no-cache           Tắt CVE cache
  --nvd-key KEY        NVD API key (nhanh hơn 10x)
```

### Usage Examples

```bash
# Quick scan
python3 recon.py -d example.com --all --depth fast

# Deep scan với interactive selection
python3 recon.py -d example.com --all --depth deep -i

# Chỉ chạy vài phases
python3 recon.py -d example.com --steps subdomain,resolve,prioritize,probe

# Full scan + delta comparison
python3 recon.py -d example.com --all --compare

# Top 5 riskiest hosts
python3 recon.py -d example.com --all --top 5
```

---

## Interactive Mode — 3 Pause Points

```
subdomain → resolve → prioritize
  ╔══════════════════════════════════════════════════╗
  ║  PAUSE 1: Select subdomains                     ║
  ║  Table: #, Score, Subdomain, Tags, IPs          ║
  ║  Input: all | 1-5,8 | high-value | top 10       ║
  ╚══════════════════════════════════════════════════╝
→ probe
  ╔══════════════════════════════════════════════════╗
  ║  PAUSE 2: Select alive hosts                    ║
  ║  Table: #, Status, Host, Title, Server, TLS     ║
  ║  Input: all | 1-5,8 | top 10                    ║
  ╚══════════════════════════════════════════════════╝
→ techdetect → port
  ╔══════════════════════════════════════════════════╗
  ║  PAUSE 3: Select by port/service                ║
  ║  Table: #, Host, IP, Open Ports, OS             ║
  ║  Input: all | 1-3,5 | top 5                     ║
  ╚══════════════════════════════════════════════════╝
→ fuzz → cve → paramfind → risk → delta → report
```

---

## File Structure

```
Mini_Recon/
├── c01.md                      ← Challenge brief
├── implementation_plan.md      ← This file
├── state_machines.md           ← State machine diagrams (Mermaid)
├── phase_reference.md          ← Detailed phase reference guide
│
└── reconrisk/
    ├── recon.py                ← CLI + 12-phase pipeline + interactive UI
    ├── requirements.txt        ← rich, requests, dnspython
    ├── setup.sh                ← Auto-install script (Linux/Kali)
    ├── README.md               ← User-facing quick start guide
    │
    ├── modules/
    │   ├── __init__.py         ← Phase registry + dependency map
    │   ├── subdomain.py        ← subfinder + assetfinder + amass + crt.sh
    │   ├── dns_resolve.py      ← DNS resolve (retry 3x + socket fallback)
    │   ├── prioritize.py       ← Scoring v2.1 (positive + negative patterns)
    │   ├── http_probe.py       ← httpx (Go) / requests probe
    │   ├── tech_detect.py      ← whatweb + header/body tech detection
    │   ├── port_scan.py        ← nmap XML parsing (top 100/1000)
    │   ├── web_fuzz.py         ← ffuf + auto-flag (admin/config/backup)
    │   ├── cve_lookup.py       ← NVD API v2 + disk cache + dedup
    │   ├── param_find.py       ← arjun → temp JSON + danger flags
    │   ├── risk_score.py       ← 0-100 composite scoring
    │   ├── delta.py            ← Baseline load/save/diff
    │   └── report.py           ← Rich tables + JSON export
    │
    ├── wordlists/
    │   └── dirs_small.txt      ← Security-focused paths (~120)
    │
    └── results/<domain>/
        ├── subdomains.txt
        ├── dns_map.json
        ├── fuzz_results.json
        ├── params.json
        ├── report.json
        └── baseline.json
```

---

## Resilience Design

### Soft Dependencies
Phases chạy khi deps thiếu data — warn nhưng không skip.

### DNS Resilience
- Retry 3x (5s → 10s → 15s timeout)
- Socket fallback nếu dnspython fail
- Root domain luôn được giữ

### Smart Filtering
| Module | Filter |
|--------|--------|
| crt.sh | Reject garbage (`xxx.comwww`), validate labels |
| prioritize | Negative scoring CDN/S3/static, filter score ≤ 0 |
| probe | Suppress InsecureRequestWarning |
| fuzz | Only status 200/301/401/403, limit 20/50 hosts, 60s/host |
| paramfind | Only status 200/301/401/403, limit 10/25 hosts, 60-90s/host |
| CVE | Dedup by host+CVE ID, severity from CVSS (not cache) |

### Graceful Degradation

| Tool | Missing? | Fallback |
|------|----------|----------|
| subfinder | Dùng source khác | crt.sh + assetfinder + DNS brute |
| assetfinder | Skip | Các source khác |
| httpx (Go) | Requests fallback | ThreadPool + requests.get |
| nmap | Skip port phase | Warn user |
| ffuf | Requests fallback | Brute-force qua requests |
| arjun | Skip param phase | Warn user |
| whatweb | Skip, dùng headers/body | HTTP header + body analysis |
| amass | Skip (deep only) | Các source khác |
| NVD API | Timeout → 0 CVEs | Cache nếu có |

---

## Prerequisites

```bash
# System deps
sudo apt-get install -y nmap python3 python3-pip golang-go

# Go tools (optional but recommended)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf/v2@latest

# Python deps
pip3 install -r requirements.txt
pip3 install arjun    # optional

# Other tools
sudo apt install amass whatweb  # optional

# PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## Verification

```bash
# Test 1: Quick fast scan
python3 recon.py -d scanme.nmap.org --all --depth fast

# Test 2: Interactive mode
python3 recon.py -d scanme.nmap.org --all --depth fast -i

# Test 3: Deep scan with real domain
python3 recon.py -d kenh14.vn --all --depth deep -i

# Test 4: Delta comparison (run twice)
python3 recon.py -d scanme.nmap.org --all --compare
python3 recon.py -d scanme.nmap.org --all --compare
```
