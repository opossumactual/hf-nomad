# hf-nomad

Simple installer and configuration tool for running NomadNet/Reticulum over HF radio using FreeDV.

## Overview

This project provides easy setup for HF mesh networking by combining:
- **freedvtnc2** - FreeDV data modem with KISS interface (proven, working)
- **Reticulum** - Cryptographic mesh networking stack
- **NomadNet** - Terminal-based communication platform

## Architecture

```
NomadNet (user interface)
    ↓
Reticulum (mesh networking)
    ↓ KISS TCP (:8001)
freedvtnc2 (FreeDV modem)
    ↓ Audio + PTT
rigctld (radio control)
    ↓ CAT
HF Radio (IC-705, FT-891, etc.)
```

## Components

### 1. install.sh
Main installer script that:
- Detects Linux distribution (Arch, Debian, Ubuntu, Fedora)
- Installs system dependencies (hamlib, codec2, python, etc.)
- Installs freedvtnc2 from pip or source
- Installs Reticulum and NomadNet
- Adds user to dialout/uucp and audio groups
- Creates directory structure

### 2. configure.sh
Interactive configuration wizard:
- Detect connected radios (scan /dev/serial/by-id/)
- List audio devices, help user select correct one
- Select radio model from hamlib list
- Set PTT method (rigctld recommended)
- Generate config files for all components

### 3. Config Files Generated

#### ~/.config/hf-nomad/config
Master config (shell sourceable):
```
RADIO_SERIAL=/dev/serial/by-id/usb-Icom_Inc._IC-705...
RADIO_MODEL=3085
AUDIO_INPUT_DEVICE=10
AUDIO_OUTPUT_DEVICE=10
FREEDV_MODE=DATAC1
RIGCTLD_PORT=4532
KISS_PORT=8001
```

#### ~/.config/freedvtnc2/config
freedvtnc2 config file:
```
input-device = 10
output-device = 10
mode = DATAC1
ptt-method = rigctld
rigctld-port = 4532
kiss-tcp-port = 8001
```

#### ~/.reticulum/config
Reticulum config with KISS interface pointing to freedvtnc2:
```
[interfaces]
  [[HF Radio]]
    type = KISSInterface
    kiss_framing = True
    port = 8001
    ...
```

#### ~/.nomadnetwork/config
NomadNet config optimized for HF:
```
try_propagation_on_send_fail = no
announce_interval = 720  # 12 hours for HF
```

### 4. Systemd Services

#### hf-nomad-rigctld.service
Starts rigctld with configured radio

#### hf-nomad-modem.service
Starts freedvtnc2 with config
Depends on rigctld

#### hf-nomad.target
Target to start/stop all HF services together

### 5. Helper Scripts

#### hf-nomad start|stop|status
Control all services

#### hf-nomad test-radio
Test CAT connection to radio

#### hf-nomad test-audio
Test audio levels

#### hf-nomad monitor
Show live status (PTT, audio levels, sync)

## File Structure

```
hf-nomad/
├── install.sh           # Main installer
├── uninstall.sh         # Clean uninstall
├── configure.sh         # Interactive config wizard
├── scripts/
│   ├── hf-nomad         # Main control script
│   ├── test-radio.sh    # Radio test
│   ├── test-audio.sh    # Audio test
│   └── detect-devices.sh
├── systemd/
│   ├── hf-nomad-rigctld.service
│   ├── hf-nomad-modem.service
│   └── hf-nomad.target
├── templates/
│   ├── freedvtnc2.conf.template
│   ├── reticulum.conf.template
│   └── nomadnetwork.conf.template
├── README.md
├── QUICKSTART.md
└── docs/
    ├── SUPPORTED_RADIOS.md
    └── TROUBLESHOOTING.md
```

## Key Learnings from oticulum

Things to carry forward:
1. Use stable /dev/serial/by-id/ paths, not /dev/ttyACM*
2. freedvtnc2 works - don't reinvent the modem
3. NomadNet config: disable try_propagation_on_send_fail for HF
4. NomadNet config: increase announce_interval for HF (6-12 hours)
5. Audio device numbers shift - detect by name not number
6. rigctld can cause issues - may need restart handling

Things NOT to do:
1. Don't write custom FreeDV modem code
2. Don't use device numbers in config (use names/paths)
3. Don't enable propagation forwarding on HF

## Supported Radios (Initial)

- Icom IC-705, IC-7300
- Yaesu FT-891, FT-991, FT-817/818
- Xiegu G90
- Any radio supported by hamlib with USB audio interface (Digirig, SignaLink, etc.)

## Target Distributions

Primary support (from day one):
- **Ubuntu 22.04, 24.04** - most common ham radio Linux
- **Debian 12 (Bookworm)** - stable server choice
- **Arch Linux** - rolling release, developer use

Future/secondary:
- Raspberry Pi OS (Debian-based)
- Fedora

### Package Differences

| Package | Arch | Debian/Ubuntu |
|---------|------|---------------|
| hamlib | `hamlib` | `libhamlib-dev libhamlib-utils` |
| codec2 | `codec2` | `libcodec2-dev` (or build from source) |
| python | `python` | `python3 python3-pip python3-venv` |
| audio | `pipewire-pulse` | `pulseaudio` or `pipewire` |
| serial group | `uucp` | `dialout` |

### freedvtnc2 Installation

freedvtnc2 requires codec2 with development headers. Options:
1. **pip install** (if codec2-dev available)
2. **Build from source** (clone xssfox/freedvtnc2, build codec2 CFFI)

Ubuntu/Debian may need codec2 built from source for latest features.

## Development Phases

### Phase 1: Basic Installer (Ubuntu/Debian + Arch) ✅ COMPLETE
- [x] Distro detection (apt vs pacman)
- [x] Install system deps for both distro families
- [x] Build codec2 from source (Debian/Ubuntu - distro packages too old)
- [x] Install freedvtnc2 via pipx
- [x] Install Reticulum + NomadNet via pipx
- [x] User group setup (dialout/uucp, audio)
- [x] Docker test suite (Debian 12, Ubuntu 24.04, Arch)

**Note:** Ubuntu 22.04 dropped - requires Python 3.11+, ships 3.10

### Phase 2: Configuration Wizard ✅ COMPLETE
- [x] Serial port detection (/dev/serial/by-id/)
- [x] Radio model selection (common radios + hamlib search)
- [x] Audio device detection and selection
- [x] PTT method selection (CAT/RTS/DTR/VOX)
- [x] FreeDV mode selection (DATAC1/DATAC3/DATAC4)
- [x] Config file generation (hf-nomad, freedvtnc2, reticulum, nomadnet)

### Phase 3: Systemd Integration
- [ ] Service files (user services)
- [ ] Start/stop/status scripts
- [ ] Status monitoring

### Phase 4: Polish
- [ ] Error handling and recovery
- [ ] Raspberry Pi testing
- [ ] Documentation
