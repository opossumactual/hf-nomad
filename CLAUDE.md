# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

hf-nomad is an installer and configuration tool for running NomadNet/Reticulum mesh networking over HF radio using FreeDV digital modes.

## Architecture

```
NomadNet (terminal UI)
    ↓
Reticulum (cryptographic mesh networking)
    ↓ KISS TCP (:8001)
freedvtnc2 (FreeDV data modem)
    ↓ Audio + PTT
rigctld (hamlib radio control)
    ↓ CAT
HF Radio
```

## Current Status

**Completed:**
- Phase 1: `install.sh` - Installs all dependencies
- Phase 2: `configure.sh` - Interactive configuration wizard

**TODO (Phase 3):**
- systemd user services for rigctld and freedvtnc2
- `hf-nomad` helper script (start/stop/status)
- Test/monitor utilities

## Project Structure

```
hf-nomad/
├── install.sh        # Main installer (distro detection, package install, codec2 build)
├── configure.sh      # Interactive setup wizard
├── test.sh           # Docker test runner
└── test/
    ├── Dockerfile.arch
    ├── Dockerfile.debian
    └── Dockerfile.ubuntu
```

## Install Script Details

`install.sh` handles:
- Distro detection: Arch, Debian 12+, Ubuntu 24.04+ (and derivatives)
- Python 3.11+ check (required by freedvtnc2)
- System packages via pacman or apt
- **codec2 source build** on Debian/Ubuntu (distro packages too old for freedvtnc2)
- pipx setup with PATH configuration
- freedvtnc2 and nomadnet installation via pipx
- User group setup (uucp/dialout for serial, audio)

## Configure Script Details

`configure.sh` provides interactive setup for:
- Serial port detection (scans `/dev/serial/by-id/`, identifies known radios)
- Manual entry option with examples
- Radio model selection (common models + hamlib search)
- Audio device selection (input/output)
- PTT method (CAT/RTS/DTR/VOX)
- FreeDV mode (DATAC1/DATAC3/DATAC4)

Generates config files:
- `~/.config/hf-nomad/config` - Master config (shell sourceable)
- `~/.config/freedvtnc2/config` - Modem settings
- `~/.reticulum/config` - Reticulum KISS interface
- `~/.nomadnetwork/config` - NomadNet settings (HF optimized)

## Target Distributions

| Distro | Version | codec2 | Notes |
|--------|---------|--------|-------|
| Arch Linux | Rolling | System package | Works directly |
| Debian | 12+ | Built from source | Package too old |
| Ubuntu | 24.04+ | Built from source | Package too old |

**Not supported:** Ubuntu 22.04 (Python 3.10, freedvtnc2 requires 3.11+)

## Testing

Docker-based testing for all supported distros:

```bash
./test.sh debian      # Test on Debian 12
./test.sh ubuntu      # Test on Ubuntu 24.04
./test.sh arch        # Test on Arch Linux
./test.sh all         # Test all distros

./test.sh debian --shell    # Debug: drop into container shell
./test.sh all --no-cache    # Rebuild without Docker cache
```

## Development Notes

**Key learnings:**
- freedvtnc2 requires codec2 with DATAC4/DATAC13 modes (not in Debian 12/Ubuntu packages)
- `$USER` env var not always set in containers - use `${USER:-$(whoami)}`
- pipx may not be in PATH immediately after install - check multiple locations
- Arch codec2 package is recent enough, Debian/Ubuntu need source build

**Do:**
- Use `/dev/serial/by-id/` paths (stable across reboots)
- Use freedvtnc2 as the modem
- Set `try_propagation_on_send_fail = no` for HF
- Use long `announce_interval` (720 min / 12 hours) for HF

**Don't:**
- Write custom FreeDV modem code
- Use device numbers in configs (they shift)
- Enable propagation forwarding on HF

## Common hamlib Model Numbers

| Radio | Model # |
|-------|---------|
| Icom IC-705 | 3085 |
| Icom IC-7300 | 3073 |
| Yaesu FT-891 | 1036 |
| Yaesu FT-991 | 1035 |
| Yaesu FT-817 | 1020 |
| Yaesu FT-818 | 1041 |
| Xiegu G90 | 3088 |
| Xiegu X6100 | 3087 |
