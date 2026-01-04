# hf-nomad

Run NomadNet/Reticulum mesh networking over HF radio using FreeDV digital modes.

## Overview

hf-nomad provides easy setup for HF mesh networking by combining:
- **freedvtnc2** - FreeDV data modem with KISS interface
- **Reticulum** - Cryptographic mesh networking stack
- **NomadNet** - Terminal-based communication platform

```
NomadNet (terminal UI)
    ↓
Reticulum (mesh networking)
    ↓ KISS TCP (:8001)
freedvtnc2 (FreeDV modem)
    ↓ Audio + PTT
rigctld (hamlib)
    ↓ CAT
HF Radio
```

## Supported Systems

| Distro | Version | Notes |
|--------|---------|-------|
| Arch Linux | Rolling | Full support |
| Debian | 12+ | Builds codec2 from source |
| Ubuntu | 24.04+ | Builds codec2 from source |

**Note:** Ubuntu 22.04 not supported (requires Python 3.11+)

## Installation

```bash
# Clone the repo
git clone https://github.com/opossumactual/hf-nomad.git
cd hf-nomad

# Install dependencies
./install.sh

# Configure (interactive)
./configure.sh
```

## Usage

### Basic Commands

```bash
hf-nomad start       # Start rigctld + freedvtnc2
hf-nomad stop        # Stop all services
hf-nomad restart     # Restart services
hf-nomad status      # Show status
```

### FreeDV Modes

```bash
hf-nomad mode            # Show current mode
hf-nomad mode DATAC1     # Fast (~980 bps, ~1.7 kHz)
hf-nomad mode DATAC3     # Moderate (~321 bps, ~0.9 kHz)
hf-nomad mode DATAC4     # Robust (~87 bps, ~0.5 kHz)
```

### Testing & Debugging

```bash
hf-nomad test-radio  # Test CAT connection
hf-nomad test-audio  # Test audio devices
hf-nomad monitor     # Follow live modem output
hf-nomad logs        # Show service logs
```

### Autostart

```bash
hf-nomad enable      # Start on login
hf-nomad disable     # Disable autostart
```

## Running NomadNet

After starting hf-nomad:

```bash
nomadnet
```

## Radio Setup

### Recommended Settings

- **Mode:** USB-D (or USB with DATA mode)
- **Filter:** Match FreeDV mode bandwidth
  - DATAC1: 2+ kHz
  - DATAC3: 1+ kHz
  - DATAC4: 0.5+ kHz
- **Power:** Start low (5-10W), increase as needed

### Supported Radios

Any radio supported by hamlib with USB audio, including:
- Icom IC-705, IC-7300
- Yaesu FT-891, FT-991, FT-817/818
- Xiegu G90, X6100
- Any radio with external interface (Digirig, SignaLink, etc.)

## Configuration Files

| File | Purpose |
|------|---------|
| `~/.config/hf-nomad/config` | Master config (shell sourceable) |
| `~/.freedvtnc2.conf` | FreeDV modem settings |
| `~/.reticulum/config` | Reticulum interfaces |
| `~/.nomadnetwork/config` | NomadNet settings |

## Troubleshooting

### Command not found / PATH issues

If `hf-nomad`, `freedvtnc2`, or `nomadnet` aren't found after install:

```bash
# Add ~/.local/bin to your PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

For **zsh** users:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

For **fish** users:
```bash
fish_add_path ~/.local/bin
```

### Service won't start

```bash
hf-nomad logs modem      # Check freedvtnc2 logs
hf-nomad logs rigctld    # Check rigctld logs
```

### Audio device issues

```bash
freedvtnc2 --list-audio-devices
```
Find your radio's USB audio interface and update `~/.freedvtnc2.conf`.

### CAT control issues

```bash
hf-nomad test-radio
```

### Check Reticulum status

```bash
rnstatus
```

## License

MIT
