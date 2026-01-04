#!/bin/bash
#
# hf-nomad uninstaller
# Removes hf-nomad components and optionally cleans up configs
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo ""
echo -e "${RED}======================================${NC}"
echo -e "${RED} hf-nomad Uninstaller${NC}"
echo -e "${RED}======================================${NC}"
echo ""

# Stop services first
info "Stopping services..."
systemctl --user stop hf-nomad-modem.service 2>/dev/null || true
systemctl --user stop hf-nomad-rigctld.service 2>/dev/null || true
systemctl --user disable hf-nomad-modem.service 2>/dev/null || true
systemctl --user disable hf-nomad-rigctld.service 2>/dev/null || true
success "Services stopped"

# Remove systemd service files
info "Removing systemd service files..."
rm -f "$HOME/.config/systemd/user/hf-nomad-rigctld.service"
rm -f "$HOME/.config/systemd/user/hf-nomad-modem.service"
rm -f "$HOME/.config/systemd/user/hf-nomad.target"
systemctl --user daemon-reload 2>/dev/null || true
success "Service files removed"

# Remove hf-nomad script
info "Removing hf-nomad script..."
rm -f "$HOME/.local/bin/hf-nomad"
success "Script removed"

# Ask about config files
echo ""
echo -e "${YELLOW}Config files:${NC}"
echo "  ~/.config/hf-nomad/"
echo "  ~/.freedvtnc2.conf"
echo ""
read -rp "Remove hf-nomad config files? [y/N]: " choice
if [[ "$choice" =~ ^[Yy] ]]; then
    rm -rf "$HOME/.config/hf-nomad"
    rm -f "$HOME/.freedvtnc2.conf"
    rm -f "$HOME/.freedvtnc2.conf.backup."* 2>/dev/null || true
    success "Config files removed"
else
    info "Keeping config files"
fi

# Ask about Reticulum/NomadNet configs
echo ""
echo -e "${YELLOW}Reticulum/NomadNet configs:${NC}"
echo "  ~/.reticulum/config"
echo "  ~/.nomadnetwork/config"
echo ""
warn "These may contain settings for other interfaces!"
read -rp "Remove Reticulum/NomadNet configs? [y/N]: " choice
if [[ "$choice" =~ ^[Yy] ]]; then
    rm -f "$HOME/.reticulum/config"
    rm -f "$HOME/.reticulum/config.backup."* 2>/dev/null || true
    rm -f "$HOME/.nomadnetwork/config"
    rm -f "$HOME/.nomadnetwork/config.backup."* 2>/dev/null || true
    success "Reticulum/NomadNet configs removed"
else
    info "Keeping Reticulum/NomadNet configs"
fi

# Ask about pipx packages
echo ""
echo -e "${YELLOW}Installed packages (via pipx):${NC}"
pipx list 2>/dev/null | grep -E "freedvtnc2|nomadnet" || echo "  (none found)"
echo ""
read -rp "Uninstall freedvtnc2? [y/N]: " choice
if [[ "$choice" =~ ^[Yy] ]]; then
    pipx uninstall freedvtnc2 2>/dev/null || warn "freedvtnc2 not installed via pipx"
    success "freedvtnc2 uninstalled"
else
    info "Keeping freedvtnc2"
fi

read -rp "Uninstall nomadnet? [y/N]: " choice
if [[ "$choice" =~ ^[Yy] ]]; then
    pipx uninstall nomadnet 2>/dev/null || warn "nomadnet not installed via pipx"
    success "nomadnet uninstalled"
else
    info "Keeping nomadnet"
fi

# Summary
echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN} Uninstall Complete${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo "Removed:"
echo "  - hf-nomad systemd services"
echo "  - hf-nomad control script"
echo ""
echo "Not removed (system packages):"
echo "  - hamlib/rigctl"
echo "  - codec2"
echo "  - pipx"
echo ""
echo "Use your package manager to remove system packages if needed."
echo ""
