"""
ReconRisk — Modular Recon Phases

Mỗi phase là một module độc lập, được đăng ký trong PHASES list.
Pipeline sẽ chạy các phase theo thứ tự này.
"""

# Phase registry — thứ tự chạy mặc định
PHASES = [
    "subdomain",
    "probe",
    "port",
    "cve",
    "risk",
    "delta",
    "report",
]

# Phase dependencies — mỗi phase cần data từ phase nào
PHASE_DEPS = {
    "subdomain": [],
    "probe": ["subdomain"],
    "port": ["subdomain"],
    "cve": ["probe", "port"],
    "risk": ["probe", "port", "cve"],
    "delta": ["risk"],
    "report": [],  # report luôn chạy nếu có bất kỳ data nào
}
