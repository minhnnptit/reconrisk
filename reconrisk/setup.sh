#!/bin/bash
# ─────────────────────────────────────────────────────
# ReconRisk — Setup Script (Linux/Debian/Ubuntu)
# Cài đặt tự động tất cả dependencies
# ─────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}═══════════════════════════════════════${NC}"
echo -e "${CYAN}  ReconRisk — Setup Script${NC}"
echo -e "${CYAN}═══════════════════════════════════════${NC}"

# ─── System packages ────────────────────────────────
echo -e "\n${YELLOW}[1/4] System packages...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq nmap python3 python3-pip golang-go curl
    echo -e "${GREEN}  ✓ System packages installed${NC}"
elif command -v yum &> /dev/null; then
    sudo yum install -y nmap python3 python3-pip golang curl
    echo -e "${GREEN}  ✓ System packages installed${NC}"
else
    echo -e "${RED}  ✗ Unsupported package manager. Install manually: nmap, python3, go${NC}"
fi

# ─── Go tools ────────────────────────────────────────
echo -e "\n${YELLOW}[2/4] Go recon tools...${NC}"

# Ensure GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin

install_go_tool() {
    local name=$1
    local url=$2
    if command -v "$name" &> /dev/null; then
        echo -e "  ${GREEN}✓ $name already installed${NC}"
    else
        echo -e "  ${CYAN}Installing $name...${NC}"
        go install -v "$url" 2>/dev/null
        if command -v "$name" &> /dev/null; then
            echo -e "  ${GREEN}✓ $name installed${NC}"
        else
            echo -e "  ${YELLOW}⚠ $name install failed (optional)${NC}"
        fi
    fi
}

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"

# ─── Python deps ─────────────────────────────────────
echo -e "\n${YELLOW}[3/4] Python dependencies...${NC}"
pip3 install -r requirements.txt -q
echo -e "${GREEN}  ✓ Python packages installed${NC}"

# ─── PATH reminder ───────────────────────────────────
echo -e "\n${YELLOW}[4/4] PATH check...${NC}"
GOBIN=$(go env GOPATH)/bin

if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo -e "${YELLOW}  ⚠ Add Go bin to your PATH:${NC}"
    echo -e "    export PATH=\$PATH:$GOBIN"
    echo -e "  ${CYAN}Or add this to your ~/.bashrc / ~/.zshrc${NC}"
else
    echo -e "${GREEN}  ✓ Go bin already in PATH${NC}"
fi

# ─── Verify ──────────────────────────────────────────
echo -e "\n${CYAN}═══════════════════════════════════════${NC}"
echo -e "${CYAN}  Tool Status${NC}"
echo -e "${CYAN}═══════════════════════════════════════${NC}"

check_tool() {
    local name=$1
    local required=$2
    if command -v "$name" &> /dev/null; then
        version=$("$name" --version 2>/dev/null | head -1 || echo "installed")
        echo -e "  ${GREEN}✓ $name${NC} — $version"
    else
        if [ "$required" = "required" ]; then
            echo -e "  ${RED}✗ $name (REQUIRED)${NC}"
        else
            echo -e "  ${YELLOW}○ $name (optional)${NC}"
        fi
    fi
}

check_tool "python3" "required"
check_tool "nmap" "optional"
check_tool "subfinder" "optional"
check_tool "httpx" "optional"
check_tool "assetfinder" "optional"

echo -e "\n${GREEN}Setup complete! Run:${NC}"
echo -e "  ${CYAN}python3 recon.py -d example.com --steps subdomain,probe${NC}"
echo ""
