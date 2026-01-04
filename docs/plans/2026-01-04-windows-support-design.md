# Windows Support Design

**Date:** 2026-01-04
**Branch:** `windows-support`

## Overview

Add Windows support to hf-nomad by replacing bash scripts with cross-platform Python scripts. Linux functionality remains unchanged.

## Target Environment

- Native Windows 10/11 (Command Prompt / PowerShell)
- No WSL or MSYS2 at runtime (MSYS2 only needed for codec2 build)

## Project Structure

```
hf-nomad/
├── configure.py               # Cross-platform config wizard (NEW)
├── hf_nomad.py                # Cross-platform launcher (NEW)
├── install.md                 # Windows install instructions (NEW)
├── install.sh                 # Linux installer (unchanged)
├── configure.sh               # Linux config wizard (unchanged)
├── requirements.txt           # Python dependencies (NEW)
├── systemd/                   # Linux only (unchanged)
└── scripts/hf-nomad           # Linux launcher (unchanged)
```

## Component Design

### 1. Configure Script (`configure.py`)

Cross-platform wizard with same flow as `configure.sh`:

1. `detect_serial_ports()` - Windows: COM ports via pyserial, Linux: /dev/serial/by-id/
2. `select_radio_model()` - Same menu, uses rigctl -l
3. `detect_audio_devices()` - Windows: sounddevice lib, Linux: freedvtnc2 --list
4. `select_ptt_method()` - Same menu (CAT/RTS/DTR/VOX)
5. `select_freedv_mode()` - Same menu (DATAC1/DATAC3/DATAC4)
6. `generate_configs()` - Write config files

**Platform-specific paths:**

| Item | Windows | Linux |
|------|---------|-------|
| Config dir | `%APPDATA%\hf-nomad\` | `~/.config/hf-nomad/` |
| Serial ports | COM3, COM4, etc. | /dev/serial/by-id/* |

**Dependencies:** pyserial, sounddevice

### 2. Launcher Script (`hf_nomad.py`)

Subprocess-based process management (no systemd):

```
hf_nomad.py start        # Start rigctld + freedvtnc2
hf_nomad.py stop         # Stop all processes
hf_nomad.py status       # Show what's running
hf_nomad.py test-radio   # Test CAT connection
hf_nomad.py test-audio   # Test audio devices
hf_nomad.py monitor      # Tail logs from processes
```

**State file:** `{config_dir}/running.json` - stores PIDs for stop/status

### 3. Windows Installation (`install.md`)

Manual installation steps:

1. Install Python 3.11+ from python.org
2. Install MSYS2 from msys2.org
3. Build codec2 in MSYS2 (documented steps)
4. Download Hamlib Windows binaries
5. `pip install freedvtnc2 nomadnet pyserial sounddevice`
6. `python configure.py`

## What's NOT Changing

- `install.sh` - Linux installer stays as-is
- `configure.sh` - Linux users can still use bash version
- `scripts/hf-nomad` - Linux launcher stays as-is
- `systemd/` - Linux services stay as-is

## Out of Scope (Future)

- Bundled codec2 DLLs
- GUI configuration tool
- Windows installer (MSI/exe)

## Dependencies

New `requirements.txt`:
```
pyserial>=3.5
sounddevice>=0.4.6
```

(freedvtnc2 and nomadnet installed separately via pip)
