#!/bin/bash
#
# hf-nomad installer v0.1.0
# Sets up NomadNet/Reticulum over HF radio using FreeDV
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global state
NEEDS_RELOGIN=""
PIPX_CMD=""

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# -----------------------------------------------------------------------------
# Check sudo availability
# -----------------------------------------------------------------------------
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        return 0  # Running as root, no sudo needed
    fi

    if ! command -v sudo &> /dev/null; then
        error "sudo is required but not installed."
    fi

    info "Checking sudo access..."
    if ! sudo -v; then
        error "Cannot obtain sudo privileges. Run with sudo or as root."
    fi
    success "sudo access confirmed"
}

# -----------------------------------------------------------------------------
# Distro Detection
# -----------------------------------------------------------------------------
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_VERSION="$VERSION_ID"
        DISTRO_NAME="$PRETTY_NAME"
    else
        error "Cannot detect distribution. /etc/os-release not found."
    fi

    case "$DISTRO_ID" in
        arch|endeavouros|manjaro)
            # Arch-based distros are rolling release, no version check needed
            DISTRO_FAMILY="arch"
            PKG_MANAGER="pacman"
            ;;
        debian)
            if [ -z "$DISTRO_VERSION" ]; then
                error "Cannot determine Debian version."
            fi
            DEBIAN_MAJOR="${DISTRO_VERSION%%.*}"
            if ! [[ "$DEBIAN_MAJOR" =~ ^[0-9]+$ ]]; then
                error "Invalid Debian version format: $DISTRO_VERSION"
            fi
            if [ "$DEBIAN_MAJOR" -lt 12 ]; then
                error "Debian $DISTRO_VERSION is not supported. Requires Debian 12+."
            fi
            DISTRO_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        ubuntu)
            if [ -z "$DISTRO_VERSION" ]; then
                error "Cannot determine Ubuntu version."
            fi
            # Extract major version (e.g., "24.04" -> "24")
            UBUNTU_MAJOR="${DISTRO_VERSION%%.*}"
            if ! [[ "$UBUNTU_MAJOR" =~ ^[0-9]+$ ]]; then
                error "Invalid Ubuntu version format: $DISTRO_VERSION"
            fi
            if [ "$UBUNTU_MAJOR" -lt 24 ]; then
                error "Ubuntu $DISTRO_VERSION is not supported. Requires Ubuntu 24.04+."
            fi
            DISTRO_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        *)
            error "Unsupported distribution: $DISTRO_ID. Supported: Arch, Debian 12+, Ubuntu 24.04+"
            ;;
    esac

    success "Detected: $DISTRO_NAME (family: $DISTRO_FAMILY)"
}

# -----------------------------------------------------------------------------
# Python Version Check
# -----------------------------------------------------------------------------
check_python() {
    info "Checking Python version..."

    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed."
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]; }; then
        error "Python $PYTHON_VERSION found, but freedvtnc2 requires Python 3.11+."
    fi

    success "Python $PYTHON_VERSION found"
}

# -----------------------------------------------------------------------------
# System Package Installation
# -----------------------------------------------------------------------------
install_system_packages() {
    info "Installing system packages..."

    case "$DISTRO_FAMILY" in
        arch)
            # Check if running as root or can sudo
            if [ "$EUID" -eq 0 ]; then
                SUDO=""
            else
                SUDO="sudo"
            fi

            $SUDO pacman -Sy --needed --noconfirm \
                base-devel \
                cmake \
                git \
                hamlib \
                codec2 \
                python-pipx \
                portaudio \
                python-pyaudio
            ;;
        debian)
            if [ "$EUID" -eq 0 ]; then
                SUDO=""
            else
                SUDO="sudo"
            fi

            $SUDO apt-get update
            $SUDO apt-get install -y \
                build-essential \
                cmake \
                git \
                libhamlib-utils \
                libhamlib-dev \
                pipx \
                portaudio19-dev \
                python3-dev \
                python3-venv
            ;;
    esac

    success "System packages installed"

    # Verify critical dependencies
    info "Verifying dependencies..."
    if ! command -v rigctl &> /dev/null; then
        error "hamlib installation failed - rigctl not found"
    fi
    success "Dependencies verified"
}

# -----------------------------------------------------------------------------
# Build codec2 from source (required for freedvtnc2 on Debian/Ubuntu)
# -----------------------------------------------------------------------------
build_codec2() {
    # Arch has recent enough codec2, only build for Debian family
    if [ "$DISTRO_FAMILY" != "debian" ]; then
        info "Using system codec2 package"
        return
    fi

    info "Building codec2 from source (Debian/Ubuntu package is too old)..."

    local BUILD_DIR="$HOME/.cache/hf-nomad-build"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Clone if not already present
    if [ -d "codec2" ]; then
        info "codec2 source already present, updating..."
        cd codec2
        git pull
    else
        git clone https://github.com/drowe67/codec2.git
        cd codec2
    fi

    # Build
    mkdir -p build_linux
    cd build_linux
    cmake ..
    make -j"$(nproc)"

    # Install
    if [ "$EUID" -eq 0 ]; then
        make install
        ldconfig
    else
        sudo make install
        sudo ldconfig
    fi

    # Return to original directory
    cd "$OLDPWD"

    success "codec2 built and installed"
}

# -----------------------------------------------------------------------------
# User Group Setup
# -----------------------------------------------------------------------------
setup_user_groups() {
    info "Setting up user groups for serial/audio access..."

    if [ "$EUID" -eq 0 ]; then
        warn "Running as root - skipping user group setup"
        return
    fi

    # Get current username (USER may not be set in some environments)
    CURRENT_USER="${USER:-$(whoami)}"
    if [ -z "$CURRENT_USER" ]; then
        warn "Cannot determine current user - skipping group setup"
        return
    fi

    case "$DISTRO_FAMILY" in
        arch)
            SERIAL_GROUP="uucp"
            ;;
        debian)
            SERIAL_GROUP="dialout"
            ;;
    esac

    # Add user to required groups
    for group in "$SERIAL_GROUP" audio; do
        if groups "$CURRENT_USER" | grep -q "\b$group\b"; then
            success "User already in $group group"
        else
            sudo usermod -aG "$group" "$CURRENT_USER"
            success "Added user to $group group"
            NEEDS_RELOGIN=1
        fi
    done
}

# -----------------------------------------------------------------------------
# pipx Setup
# -----------------------------------------------------------------------------
setup_pipx() {
    info "Setting up pipx..."

    # Find pipx - may not be in PATH immediately after install
    if command -v pipx &> /dev/null; then
        PIPX_CMD="pipx"
    elif [ -x /usr/bin/pipx ]; then
        PIPX_CMD="/usr/bin/pipx"
    elif [ -x "$HOME/.local/bin/pipx" ]; then
        PIPX_CMD="$HOME/.local/bin/pipx"
    else
        error "pipx not found after installation. Check package installation."
    fi

    # Ensure pipx path is configured
    $PIPX_CMD ensurepath

    # Source the updated PATH for this session
    export PATH="$HOME/.local/bin:$PATH"

    success "pipx configured"
}

# -----------------------------------------------------------------------------
# Install freedvtnc2
# -----------------------------------------------------------------------------
install_freedvtnc2() {
    info "Installing freedvtnc2..."

    if $PIPX_CMD list 2>/dev/null | grep -q freedvtnc2; then
        warn "freedvtnc2 already installed, reinstalling..."
        if ! $PIPX_CMD reinstall freedvtnc2; then
            error "freedvtnc2 reinstallation failed"
        fi
    else
        if ! $PIPX_CMD install freedvtnc2 2>&1; then
            echo ""
            error "freedvtnc2 installation failed.

This often means codec2 headers are incompatible or missing.
Try building codec2 from source:

  git clone https://github.com/drowe67/codec2.git
  cd codec2 && mkdir build && cd build
  cmake .. && make && sudo make install
  sudo ldconfig

Then run this installer again."
        fi
    fi

    # Verify installation
    if command -v freedvtnc2 &> /dev/null || [ -x "$HOME/.local/bin/freedvtnc2" ]; then
        success "freedvtnc2 installed"
    else
        error "freedvtnc2 installation failed - binary not found"
    fi
}

# -----------------------------------------------------------------------------
# Install NomadNet (includes Reticulum)
# -----------------------------------------------------------------------------
install_nomadnet() {
    info "Installing NomadNet (includes Reticulum)..."

    if $PIPX_CMD list 2>/dev/null | grep -q nomadnet; then
        warn "nomadnet already installed, reinstalling..."
        if ! $PIPX_CMD reinstall nomadnet; then
            error "NomadNet reinstallation failed"
        fi
    else
        if ! $PIPX_CMD install nomadnet; then
            error "NomadNet installation failed"
        fi
    fi

    # Verify installation
    if command -v nomadnet &> /dev/null || [ -x "$HOME/.local/bin/nomadnet" ]; then
        success "NomadNet installed"
    else
        error "NomadNet installation failed - binary not found"
    fi
}

# -----------------------------------------------------------------------------
# Create Config Directory
# -----------------------------------------------------------------------------
create_config_dir() {
    info "Creating hf-nomad config directory..."

    mkdir -p "$HOME/.config/hf-nomad"

    success "Config directory created: ~/.config/hf-nomad"
}

# -----------------------------------------------------------------------------
# Print Summary
# -----------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN} hf-nomad installation complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo "Installed components:"
    echo "  - freedvtnc2 (FreeDV TNC)"
    echo "  - nomadnet (includes Reticulum)"
    echo "  - hamlib (rigctld)"
    echo ""
    echo "Next steps:"
    echo "  1. Run: source ~/.bashrc  (or restart your terminal)"
    echo "  2. Run: ./configure.sh    (coming soon)"
    echo ""

    if [ -n "$NEEDS_RELOGIN" ]; then
        echo -e "${YELLOW}NOTE: You were added to new groups.${NC}"
        echo -e "${YELLOW}Log out and back in for serial port access.${NC}"
        echo ""
    fi

    echo "Quick test commands:"
    echo "  freedvtnc2 --help"
    echo "  nomadnet --help"
    echo "  rigctl --version"
    echo ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE} hf-nomad Installer - Phase 1${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""

    detect_distro
    check_sudo
    check_python
    install_system_packages
    build_codec2
    setup_user_groups
    setup_pipx
    install_freedvtnc2
    install_nomadnet
    create_config_dir
    print_summary
}

main "$@"
