# ReconRisk v2 — Modular Recon CLI

**Full recon pipeline with interactive target selection and risk scoring.**

```
[Quick scan]     python3 recon.py -d target.com --all --depth fast
[Deep + select]  python3 recon.py -d target.com --all --depth deep -i
[Delta diff]     python3 recon.py -d target.com --all --compare
```

---

## 🚀 Quick Start

```bash
# 1. Setup
chmod +x setup.sh && ./setup.sh
pip3 install -r requirements.txt

# 2. Run
python3 recon.py -d example.com --all --depth fast
```

---

## 📋 Pipeline (12 Phases)

```
subdomain → resolve → prioritize → [PAUSE 1] → probe → [PAUSE 2]
→ techdetect → port → [PAUSE 3] → fuzz → cve → paramfind
→ risk → delta → report
```

| Phase | Tool | Description |
|-------|------|-------------|
| subdomain | subfinder + assetfinder + amass + crt.sh | Multi-source enumeration |
| resolve | dnspython + socket fallback | A/AAAA/CNAME + takeover detect |
| prioritize | Scoring engine | Score by prefix/CNAME/IP uniqueness |
| probe | httpx / requests | HTTP status, TLS, title, server |
| techdetect | whatweb + headers/body | CMS, framework, language detect |
| port | nmap (top 100/1000) | Open ports + service versions |
| fuzz | ffuf | Directory/file discovery + auto-flag |
| cve | NVD API v2 + cache | CVE lookup by service + tech stack |
| paramfind | arjun | Hidden parameter discovery |
| risk | Scoring engine | 0-100 composite risk score |
| delta | Baseline diff | NEW / GONE / CHANGED detection |
| report | Rich tables + JSON | Formatted output + export |

---

## 🎯 Interactive Mode (`-i`)

Pause after key phases to review and select targets:

```bash
python3 recon.py -d example.com --all --depth deep -i
```

| Pause | After | User Decides |
|-------|-------|-------------|
| **1** | prioritize | Select subdomains (by score, tag, or number) |
| **2** | probe | Select alive hosts (skip 503/dead) |
| **3** | port | Select hosts by open ports/services |

Selection syntax: `all` | `1-5,8,12` | `top 10` | `high-value` (tag name)

---

## ⚙️ CLI Options

| Option | Description |
|--------|-------------|
| `-d DOMAIN` | Target domain (required) |
| `--all` | Run all 12 phases |
| `--steps phase1,phase2` | Run specific phases |
| `--depth fast\|deep` | Fast (top 100 ports) / Deep (top 1000 + amass) |
| `-i, --interactive` | Enable interactive target selection |
| `--compare` | Compare with previous scan baseline |
| `--top N` | Show only top-N riskiest hosts |
| `--timeout N` | Timeout per phase in seconds (default: 120) |
| `--threads N` | Concurrency level (default: 10) |
| `--no-cache` | Disable CVE cache |
| `--nvd-key KEY` | NVD API key for faster queries |

---

## 🏗 Architecture

```
reconrisk/
├── recon.py                ← CLI + pipeline + interactive selection
├── requirements.txt
├── setup.sh                ← Auto-install (Linux/Kali)
├── modules/
│   ├── __init__.py         ← 12 phases + dependency map
│   ├── subdomain.py        ← subfinder + assetfinder + amass + crt.sh
│   ├── dns_resolve.py      ← dnspython resolve + CNAME takeover
│   ├── prioritize.py       ← Scoring + wildcard filter
│   ├── http_probe.py       ← httpx + requests fallback
│   ├── tech_detect.py      ← whatweb + header/body analysis
│   ├── port_scan.py        ← nmap XML parsing
│   ├── web_fuzz.py         ← ffuf + auto-flag admin/config/backup
│   ├── cve_lookup.py       ← NVD API v2 + disk cache
│   ├── param_find.py       ← arjun + danger flags (SSRF/LFI/RCE)
│   ├── risk_score.py       ← 0-100 composite scoring
│   ├── delta.py            ← Baseline diff
│   └── report.py           ← Rich tables + JSON export
├── wordlists/
│   └── dirs_small.txt      ← Security-focused paths (120 entries)
└── results/<domain>/
    ├── subdomains.txt
    ├── dns_map.json
    ├── fuzz_results.json
    ├── report.json
    └── baseline.json
```

---

## 📊 Risk Scoring (0-100)

| Signal | Points |
|--------|--------|
| CRITICAL CVE (CVSS ≥ 9.0) | +40 |
| HIGH CVE (CVSS 7.0-8.9) | +25 |
| MEDIUM CVE (CVSS 4.0-6.9) | +10 (max 20) |
| Subdomain takeover | +40 |
| Config leak (.git, .env) | +20 |
| Sensitive ports (22, 3306...) | +15 |
| Backup files found | +15 |
| Dangerous params (SSRF/LFI/RCE) | +15 |
| Admin panel found | +10 |
| Admin ports (8080, 9000...) | +10 |
| HTTP only (no HTTPS) | +10 |

| Score | Band |
|-------|------|
| ≥ 70 | 🔴 CRITICAL |
| 50-69 | 🟠 HIGH |
| 30-49 | 🟡 MEDIUM |
| < 30 | 🟢 LOW |

---

## 🧰 Tool Dependencies

| Tool | Required? | Install |
|------|-----------|---------|
| Python 3.8+ | ✅ Yes | - |
| nmap | Optional | `apt install nmap` |
| subfinder | Optional | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | Optional | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| assetfinder | Optional | `go install github.com/tomnomnom/assetfinder@latest` |
| ffuf | Optional | `go install github.com/ffuf/ffuf/v2@latest` |
| arjun | Optional | `pip3 install arjun` |
| amass | Optional | `apt install amass` |
| whatweb | Optional | `apt install whatweb` |

All optional tools have fallbacks — the pipeline runs with whatever is available.

---

## 📄 License

MIT
