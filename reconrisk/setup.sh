#!/bin/bash
# ─────────────────────────────────────────────────────
# ReconRisk v2 — Setup Script (Linux/Debian/Kali)
# ─────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}═══════════════════════════════════════${NC}"
echo -e "${CYAN}  ReconRisk v2 — Setup Script${NC}"
echo -e "${CYAN}═══════════════════════════════════════${NC}"

# ─── System packages ────────────────────────────────
echo -e "\n${YELLOW}[1/5] System packages...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq nmap python3 python3-pip golang-go curl whatweb
    echo -e "${GREEN}  ✓ System packages installed${NC}"
elif command -v yum &> /dev/null; then
    sudo yum install -y nmap python3 python3-pip golang curl
    echo -e "${GREEN}  ✓ System packages installed${NC}"
else
    echo -e "${RED}  ✗ Unsupported package manager${NC}"
fi

# ─── Go tools ────────────────────────────────────────
echo -e "\n${YELLOW}[2/5] Go recon tools...${NC}"

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

# ffuf
install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"

# ─── Python tools ────────────────────────────────────
echo -e "\n${YELLOW}[3/5] Python tools...${NC}"
pip3 install -r requirements.txt -q

# arjun
if command -v arjun &> /dev/null; then
    echo -e "  ${GREEN}✓ arjun already installed${NC}"
else
    echo -e "  ${CYAN}Installing arjun...${NC}"
    pip3 install arjun -q
    echo -e "  ${GREEN}✓ arjun installed${NC}"
fi

# ─── Optional: amass ─────────────────────────────────
echo -e "\n${YELLOW}[4/5] Optional tools...${NC}"
if command -v amass &> /dev/null; then
    echo -e "  ${GREEN}✓ amass already installed${NC}"
else
    echo -e "  ${CYAN}Installing amass...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y -qq amass 2>/dev/null || \
            go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null
    else
        go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null
    fi
    if command -v amass &> /dev/null; then
        echo -e "  ${GREEN}✓ amass installed${NC}"
    else
        echo -e "  ${YELLOW}⚠ amass install failed (optional — deep mode only)${NC}"
    fi
fi

# ─── PATH persistence ────────────────────────────────
echo -e "\n${YELLOW}[5/5] PATH setup...${NC}"
GOBIN=$(go env GOPATH)/bin
PATH_LINE="export PATH=\$PATH:$GOBIN"

if [ -f "$HOME/.bashrc" ]; then
    if ! grep -q "$(go env GOPATH)/bin" "$HOME/.bashrc" 2>/dev/null; then
        echo "" >> "$HOME/.bashrc"
        echo "# ReconRisk: Go tools PATH" >> "$HOME/.bashrc"
        echo "$PATH_LINE" >> "$HOME/.bashrc"
        echo -e "${GREEN}  ✓ Added Go bin to ~/.bashrc${NC}"
    else
        echo -e "${GREEN}  ✓ Go bin already in ~/.bashrc${NC}"
    fi
fi

if [ -f "$HOME/.zshrc" ]; then
    if ! grep -q "$(go env GOPATH)/bin" "$HOME/.zshrc" 2>/dev/null; then
        echo "" >> "$HOME/.zshrc"
        echo "# ReconRisk: Go tools PATH" >> "$HOME/.zshrc"
        echo "$PATH_LINE" >> "$HOME/.zshrc"
        echo -e "${GREEN}  ✓ Added Go bin to ~/.zshrc${NC}"
    else
        echo -e "${GREEN}  ✓ Go bin already in ~/.zshrc${NC}"
    fi
fi

export PATH=$PATH:$GOBIN

# ─── Verify ──────────────────────────────────────────
echo -e "\n${CYAN}═══════════════════════════════════════${NC}"
echo -e "${CYAN}  Tool Status${NC}"
echo -e "${CYAN}═══════════════════════════════════════${NC}"

check_tool() {
    local name=$1
    local required=$2
    if command -v "$name" &> /dev/null; then
        echo -e "  ${GREEN}✓ $name${NC}"
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
check_tool "ffuf" "optional"
check_tool "arjun" "optional"
check_tool "amass" "optional"
check_tool "whatweb" "optional"

echo -e "\n${GREEN}Setup complete! Run:${NC}"
echo -e "  ${CYAN}python3 recon.py -d example.com --all --depth fast${NC}"
echo ""
