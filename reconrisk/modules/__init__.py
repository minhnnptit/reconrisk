"""
ReconRisk v2 — Modular Recon Phases (12 phases)

Pipeline: subdomain → resolve → prioritize → probe → techdetect
          → port → fuzz → cve → paramfind → risk → delta → report
"""

# Phase registry — thứ tự chạy mặc định
PHASES = [
    "subdomain",    # amass + subfinder + assetfinder + crt.sh
    "resolve",      # DNS resolve → IPs, CNAME detect
    "prioritize",   # Score + filter subdomains
    "probe",        # HTTP alive check
    "techdetect",   # whatweb + header/body patterns
    "port",         # nmap on unique IPs
    "fuzz",         # ffuf directory scan
    "cve",          # NVD API (service + tech stack)
    "paramfind",    # arjun parameter discovery
    "risk",         # scoring 0-100
    "delta",        # baseline diff
    "report",       # terminal + JSON
]

# Phase dependencies
PHASE_DEPS = {
    "subdomain":  [],
    "resolve":    ["subdomain"],
    "prioritize": ["resolve"],
    "probe":      ["prioritize"],
    "techdetect": ["probe"],
    "port":       ["resolve"],
    "fuzz":       ["probe"],
    "cve":        ["port", "techdetect"],
    "paramfind":  ["probe"],
    "risk":       ["probe", "port", "cve"],
    "delta":      ["risk"],
    "report":     [],
}
