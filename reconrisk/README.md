# ReconRisk — Modular Recon CLI

**Chọn đúng phase cần chạy, ở độ sâu cần thiết — và phát hiện thay đổi bề mặt tấn công giữa các lần scan.**

```
[Quick check]    python3 recon.py -d target.com --steps subdomain,probe
[Deep dive]      python3 recon.py -d target.com --steps subdomain,port,cve --depth deep
[Full + diff]    python3 recon.py -d target.com --all --compare
```

---

## 🚀 Quick Start

### 1. Setup (Linux)

```bash
chmod +x setup.sh
./setup.sh
```

### 2. Install Python deps

```bash
pip3 install -r requirements.txt
```

### 3. Run

```bash
# Chỉ subdomain enum
python3 recon.py -d example.com --steps subdomain

# Subdomain → probe → risk
python3 recon.py -d example.com --steps subdomain,probe,risk

# Full scan, deep mode
python3 recon.py -d example.com --all --depth deep --top 10

# Full scan + compare with previous baseline
python3 recon.py -d example.com --all --compare
```

---

## 📋 Features

| Feature                  | Description                                    |
|--------------------------|------------------------------------------------|
| `--steps`                | Chọn phase: subdomain, probe, port, cve, risk, delta |
| `--depth fast\|deep`     | Fast (top 100 ports) vs Deep (top 1000 ports)  |
| CVE Enrichment           | NVD API v2 + disk cache                        |
| Risk Score 0–100         | CVSS + sensitive ports + HTTPS check           |
| `--compare` Delta Diff   | NEW / GONE / CHANGED giữa 2 lần scan          |
| Rich Terminal Output     | Colored table, sorted by risk                  |

---

## 🏗 Architecture

```
reconrisk/
├── recon.py                ← CLI entry point (argparse + pipeline)
├── requirements.txt        ← rich, requests, dnspython
├── setup.sh                ← Auto-install script (Linux)
├── modules/
│   ├── __init__.py         ← Phase registry + dependency map
│   ├── subdomain.py        ← subfinder + assetfinder + DNS fallback
│   ├── http_probe.py       ← httpx + requests fallback
│   ├── port_scan.py        ← nmap XML parsing
│   ├── cve_lookup.py       ← NVD API v2 + disk cache
│   ├── risk_score.py       ← Pure computation, 0–100 scoring
│   ├── delta.py            ← Baseline load/save/diff
│   └── report.py           ← Rich table + JSON export
└── results/
    └── <domain>/
        ├── subdomains.txt
        ├── report.json
        └── baseline.json
```

### Pipeline Flow

```
CLI Args → Validate → Build Phase List → Run Phases → Report
                                              │
                        ┌─────────────────────┤
                        ▼                     ▼
                   Subdomain ──→ Probe ──→ Port Scan
                                  │          │
                                  ▼          ▼
                              CVE Lookup ←───┘
                                  │
                                  ▼
                              Risk Score
                                  │
                              ┌───┴───┐
                              ▼       ▼
                           Delta   Report
```

### Graceful Degradation

| Tool         | Missing?                                |
|--------------|-----------------------------------------|
| `subfinder`  | Fallback: dnspython brute resolve       |
| `assetfinder`| Skip silently                           |
| `httpx`      | Fallback: requests.get()                |
| `nmap`       | Skip port phase, warn user              |
| NVD API      | Timeout → score with 0 CVEs             |

---

## 🧰 Prerequisites

- **Python 3.8+** (required)
- **nmap** (optional — for port scanning)
- **Go tools** (optional — for faster recon):
  - `subfinder` — subdomain enumeration
  - `httpx` — HTTP probing
  - `assetfinder` — additional subdomain sources

---

## 📊 Risk Scoring

| Signal                           | Points      |
|----------------------------------|-------------|
| CRITICAL CVE (CVSS ≥ 9.0)       | +40         |
| HIGH CVE (CVSS 7.0–8.9)         | +25         |
| MEDIUM CVE (CVSS 4.0–6.9)       | +10 (max 20)|
| Sensitive ports (22, 3306...)    | +15         |
| Admin ports (8080, 9000...)      | +10         |
| HTTP only (no HTTPS)             | +10         |

| Score  | Band     |
|--------|----------|
| ≥ 70   | 🔴 CRITICAL |
| 50–69  | 🟠 HIGH     |
| 30–49  | 🟡 MEDIUM   |
| < 30   | 🟢 LOW      |

---

## 📄 License

MIT
