#!/bin/bash
#
# Test runner for hf-nomad installer
# Tests the installer in Docker containers for each supported distro
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

# Available distros
DISTROS="debian ubuntu arch"

usage() {
    echo "Usage: $0 [distro|all]"
    echo ""
    echo "Distros: $DISTROS"
    echo ""
    echo "Examples:"
    echo "  $0 debian    # Test on Debian 12"
    echo "  $0 ubuntu    # Test on Ubuntu 24.04"
    echo "  $0 arch      # Test on Arch Linux"
    echo "  $0 all       # Test on all distros"
    echo ""
    echo "Options:"
    echo "  --shell      # Drop into shell instead of running installer"
    echo "  --no-cache   # Build without Docker cache"
    exit 1
}

test_distro() {
    local distro=$1
    local shell_mode=$2
    local no_cache=$3
    local dockerfile="$TEST_DIR/Dockerfile.$distro"

    if [ ! -f "$dockerfile" ]; then
        fail "Dockerfile not found: $dockerfile"
        return 1
    fi

    info "Testing on $distro..."

    # Build args
    local build_args=""
    if [ "$no_cache" = "true" ]; then
        build_args="--no-cache"
    fi

    # Build the test image
    info "Building Docker image for $distro..."
    if ! docker build $build_args -t "hf-nomad-test-$distro" -f "$dockerfile" "$SCRIPT_DIR" 2>&1; then
        fail "Docker build failed for $distro"
        return 1
    fi

    # Run the test
    if [ "$shell_mode" = "true" ]; then
        info "Dropping into shell on $distro..."
        docker run --rm -it "hf-nomad-test-$distro" /bin/bash
    else
        info "Running installer on $distro..."
        if docker run --rm "hf-nomad-test-$distro" 2>&1; then
            pass "$distro"
            return 0
        else
            fail "$distro"
            return 1
        fi
    fi
}

# Parse arguments
SHELL_MODE="false"
NO_CACHE="false"
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --shell)
            SHELL_MODE="true"
            shift
            ;;
        --no-cache)
            NO_CACHE="true"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage
fi

# Run tests
echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE} hf-nomad Installer Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

FAILED=0
PASSED=0

if [ "$TARGET" = "all" ]; then
    for distro in $DISTROS; do
        if test_distro "$distro" "$SHELL_MODE" "$NO_CACHE"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
        echo ""
    done
else
    if echo "$DISTROS" | grep -qw "$TARGET"; then
        if test_distro "$TARGET" "$SHELL_MODE" "$NO_CACHE"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
    else
        fail "Unknown distro: $TARGET"
        echo "Available: $DISTROS"
        exit 1
    fi
fi

# Summary
echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE} Summary${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "  Passed: ${GREEN}$PASSED${NC}"
echo -e "  Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
    exit 1
fi
