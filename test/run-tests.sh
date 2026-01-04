#!/bin/bash
#
# Test runner for hf-nomad (runs inside Docker container)
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

FAILED=0

# Ensure ~/.local/bin is in PATH (pipx installs there)
export PATH="$HOME/.local/bin:$PATH"

check() {
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc"
        ((FAILED++))
    fi
}

echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE} hf-nomad Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# Phase 1: Install
# -----------------------------------------------------------------------------
info "Phase 1: Running install.sh..."
./install.sh
echo ""

# Verify installation
info "Verifying Phase 1 installation..."

check "freedvtnc2 installed" command -v freedvtnc2
check "nomadnet installed" command -v nomadnet
check "rigctl installed" command -v rigctl

# Note: rnsd is internal to nomadnet's pipx venv, not a separate command

echo ""

# -----------------------------------------------------------------------------
# Phase 3: Service files and hf-nomad script
# -----------------------------------------------------------------------------
info "Phase 3: Testing service installation..."

# Manually install services (configure.sh is interactive, so we do it directly)
mkdir -p "$HOME/.config/systemd/user"
mkdir -p "$HOME/.local/bin"

cp systemd/hf-nomad-rigctld.service "$HOME/.config/systemd/user/"
cp systemd/hf-nomad-modem.service "$HOME/.config/systemd/user/"
cp systemd/hf-nomad.target "$HOME/.config/systemd/user/"
cp scripts/hf-nomad "$HOME/.local/bin/"
chmod +x "$HOME/.local/bin/hf-nomad"

check "rigctld service installed" test -f "$HOME/.config/systemd/user/hf-nomad-rigctld.service"
check "modem service installed" test -f "$HOME/.config/systemd/user/hf-nomad-modem.service"
check "target installed" test -f "$HOME/.config/systemd/user/hf-nomad.target"
check "hf-nomad script installed" test -x "$HOME/.local/bin/hf-nomad"

echo ""

# -----------------------------------------------------------------------------
# Test hf-nomad script
# -----------------------------------------------------------------------------
info "Testing hf-nomad script..."

# Test help command
check "hf-nomad help runs" hf-nomad help

# Test syntax (bash -n)
check "hf-nomad syntax valid" bash -n "$HOME/.local/bin/hf-nomad"

# Test service file syntax (basic validation)
info "Validating service file syntax..."
for svc in rigctld modem; do
    file="$HOME/.config/systemd/user/hf-nomad-$svc.service"
    if grep -q '^\[Unit\]' "$file" && grep -q '^\[Service\]' "$file"; then
        pass "hf-nomad-$svc.service has valid structure"
    else
        fail "hf-nomad-$svc.service missing sections"
        ((FAILED++))
    fi
done

echo ""

# -----------------------------------------------------------------------------
# Test with mock config
# -----------------------------------------------------------------------------
info "Testing with mock configuration..."

mkdir -p "$HOME/.config/hf-nomad"
cat > "$HOME/.config/hf-nomad/config" << 'EOF'
RADIO_SERIAL="none"
RADIO_MODEL="none"
RADIO_MODEL_NAME="None (VOX)"
AUDIO_INPUT_DEVICE="0"
AUDIO_OUTPUT_DEVICE="0"
FREEDV_MODE="DATAC1"
PTT_METHOD="none"
RIGCTLD_PORT="4532"
KISS_PORT="8001"
EOF

# Test status command (will show stopped services, but should not error)
check "hf-nomad status runs with config" hf-nomad status

echo ""

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE} Test Summary${NC}"
echo -e "${BLUE}======================================${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAILED test(s) failed${NC}"
    exit 1
fi
