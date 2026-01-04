#!/usr/bin/env python3
"""
hf-nomad configuration wizard v0.1.0
Cross-platform interactive setup for radio, audio, and PTT configuration
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

# Try to import optional dependencies
try:
    import serial.tools.list_ports
    HAS_PYSERIAL = True
except ImportError:
    HAS_PYSERIAL = False

try:
    import sounddevice as sd
    HAS_SOUNDDEVICE = True
except ImportError:
    HAS_SOUNDDEVICE = False

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')

# ANSI colors (disabled on Windows if not supported)
if IS_WINDOWS:
    # Enable ANSI on Windows 10+
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        USE_COLOR = True
    except Exception:
        USE_COLOR = False
else:
    USE_COLOR = True

if USE_COLOR:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'
else:
    RED = GREEN = YELLOW = BLUE = CYAN = BOLD = NC = ''


def info(msg):
    print(f"{BLUE}[INFO]{NC} {msg}")

def success(msg):
    print(f"{GREEN}[OK]{NC} {msg}")

def warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")

def error(msg):
    print(f"{RED}[ERROR]{NC} {msg}")
    sys.exit(1)

def header(msg):
    print(f"\n{BOLD}{CYAN}=== {msg} ==={NC}\n")


def get_config_dir():
    """Get platform-appropriate config directory."""
    if IS_WINDOWS:
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
        return Path(base) / 'hf-nomad'
    else:
        return Path.home() / '.config' / 'hf-nomad'


def get_freedvtnc2_config_path():
    """Get freedvtnc2 config file path."""
    # freedvtnc2 uses ~/.freedvtnc2.conf on all platforms
    return Path.home() / '.freedvtnc2.conf'


def get_reticulum_config_path():
    """Get Reticulum config file path."""
    if IS_WINDOWS:
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
        return Path(base) / 'Reticulum' / 'config'
    else:
        return Path.home() / '.reticulum' / 'config'


def confirm_overwrite(filepath, name):
    """Ask to overwrite existing config. Returns True if should write."""
    if filepath.exists():
        print()
        warn(f"{name} config already exists: {filepath}")
        choice = input("Overwrite? (backup will be created) [y/N]: ").strip().lower()
        if choice in ('y', 'yes'):
            backup = filepath.with_suffix(f'.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
            shutil.copy(filepath, backup)
            info(f"Backed up to {backup}")
            return True
        else:
            info(f"Skipping {name} config")
            return False
    return True


# Common radio models
RADIO_MODELS = [
    ('3085', 'Icom IC-705'),
    ('3073', 'Icom IC-7300'),
    ('3078', 'Icom IC-7610'),
    ('1036', 'Yaesu FT-891'),
    ('1035', 'Yaesu FT-991/991A'),
    ('1020', 'Yaesu FT-817'),
    ('1041', 'Yaesu FT-818'),
    ('3088', 'Xiegu G90'),
    ('3087', 'Xiegu X6100'),
]


class Config:
    """Holds configuration state."""
    def __init__(self):
        self.radio_serial = ''
        self.radio_model = ''
        self.radio_model_name = ''
        self.audio_input = ''
        self.audio_output = ''
        self.ptt_method = ''
        self.freedv_mode = 'DATAC1'
        self.rigctld_port = '4532'
        self.kiss_port = '8001'


def detect_serial_ports_windows():
    """Detect serial ports on Windows using pyserial."""
    if not HAS_PYSERIAL:
        warn("pyserial not installed. Install with: pip install pyserial")
        return []

    ports = []
    for port in serial.tools.list_ports.comports():
        desc = port.description or 'Unknown'
        # Try to identify known radios
        if 'IC-705' in desc.upper():
            desc = f"Icom IC-705 (detected) - {port.device}"
        elif 'IC-7300' in desc.upper():
            desc = f"Icom IC-7300 (detected) - {port.device}"
        elif 'G90' in desc.upper():
            desc = f"Xiegu G90 (detected) - {port.device}"
        elif 'CP210' in desc.upper() or 'Silicon Labs' in desc:
            desc = f"USB-Serial (CP210x) - Digirig/Generic - {port.device}"
        elif 'FTDI' in desc.upper() or 'FT232' in desc.upper():
            desc = f"USB-Serial (FTDI) - Generic - {port.device}"
        elif 'CH340' in desc.upper() or 'CH341' in desc.upper():
            desc = f"USB-Serial (CH340) - Generic - {port.device}"
        ports.append((port.device, desc))
    return ports


def detect_serial_ports_linux():
    """Detect serial ports on Linux using /dev/serial/by-id/."""
    ports = []
    by_id = Path('/dev/serial/by-id')

    if by_id.exists():
        for port in by_id.iterdir():
            port_str = str(port)
            name = port.name

            # Try to identify known radios
            if 'IC-705' in name or 'Icom' in name and '705' in name:
                desc = "Icom IC-705 (detected)"
            elif 'IC-7300' in name or 'Icom' in name and '7300' in name:
                desc = "Icom IC-7300 (detected)"
            elif 'G90' in name or 'Xiegu' in name:
                desc = "Xiegu G90 (detected)"
            elif 'Silicon_Labs' in name or 'CP210' in name:
                desc = "USB-Serial (CP210x) - Digirig/Generic"
            elif 'FTDI' in name or 'FT232' in name:
                desc = "USB-Serial (FTDI) - Generic"
            elif 'CH340' in name or 'CH341' in name:
                desc = "USB-Serial (CH340) - Generic"
            else:
                desc = "USB-Serial"

            ports.append((port_str, f"{desc}\n      {name}"))

    return ports


def detect_serial_ports(config):
    """Detect and select serial port."""
    header("Serial Port Detection")

    if IS_WINDOWS:
        ports = detect_serial_ports_windows()
    else:
        ports = detect_serial_ports_linux()

    if not ports:
        warn("No serial ports found.")
        print("This is normal if:")
        print("  - Your radio is not connected")
        print("  - You're using VOX-only (no CAT control)")
        print("  - Your interface uses a different connection method")
        print()
    else:
        print("Found serial ports:")
        print()
        for i, (port, desc) in enumerate(ports, 1):
            print(f"  {BOLD}[{i}]{NC} {desc}")
            if IS_WINDOWS:
                pass  # Description includes port
            print()

    print(f"  {BOLD}[M]{NC} Manual entry (type path)")
    print(f"  {BOLD}[N]{NC} None (VOX only, no CAT control)")
    print()

    while True:
        choice = input(f"Select serial port [1-{len(ports)}/M/N]: ").strip()

        if choice.upper() == 'N':
            config.radio_serial = 'none'
            success("No serial port (VOX mode)")
            return

        if choice.upper() == 'M':
            print()
            if IS_WINDOWS:
                print("Examples: COM3, COM4, COM5")
            else:
                print("Examples:")
                print("  /dev/ttyUSB0")
                print("  /dev/ttyACM0")
                print("  /dev/serial/by-id/usb-Silicon_Labs_CP210x...")
            print()
            port = input("Enter serial port path: ").strip()
            if IS_WINDOWS or Path(port).exists():
                config.radio_serial = port
                success(f"Selected: {port}")
                return
            else:
                warn(f"Port does not exist: {port}")
                continue

        try:
            idx = int(choice)
            if 1 <= idx <= len(ports):
                config.radio_serial = ports[idx - 1][0]
                success(f"Selected: {config.radio_serial}")
                return
        except ValueError:
            pass

        warn("Invalid choice")


def select_radio_model(config):
    """Select radio model for hamlib."""
    header("Radio Model Selection")

    if config.radio_serial == 'none':
        config.radio_model = 'none'
        config.radio_model_name = 'None (VOX)'
        info("Skipping radio model selection (VOX mode)")
        return

    # Check if rigctl is available
    rigctl_cmd = 'rigctl.exe' if IS_WINDOWS else 'rigctl'
    if not shutil.which(rigctl_cmd):
        warn(f"{rigctl_cmd} not found. Make sure hamlib is installed and in PATH.")

    print("Common radio models:")
    print()
    for i, (model, name) in enumerate(RADIO_MODELS, 1):
        print(f"  {BOLD}[{i}]{NC} {name:<20} (model {model})")
    print()
    print(f"  {BOLD}[S]{NC} Search hamlib models")
    print(f"  {BOLD}[M]{NC} Manual entry (enter model number)")
    print()

    while True:
        choice = input(f"Select radio model [1-{len(RADIO_MODELS)}/S/M]: ").strip()

        if choice.upper() == 'S':
            search = input("Search for radio (e.g., 'kenwood', '7300'): ").strip()
            print()
            try:
                result = subprocess.run(
                    [rigctl_cmd, '-l'],
                    capture_output=True, text=True, timeout=10
                )
                print(f"{BOLD}Model#  Manufacturer         Radio{NC}")
                print("------  ------------         -----")
                for line in result.stdout.splitlines():
                    if search.lower() in line.lower():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].isdigit():
                            print(f"{parts[0]:<7} {parts[1]:<20} {' '.join(parts[2:])}")
                print()
            except Exception as e:
                warn(f"Could not run rigctl: {e}")

            model = input("Enter model number from first column: ").strip()
            if model:
                config.radio_model = model
                config.radio_model_name = f"Hamlib model {model}"
                success(f"Selected: {config.radio_model_name}")
                return
            continue

        if choice.upper() == 'M':
            print()
            print("Tip: Find model numbers with: rigctl -l | less")
            print("Examples: IC-705=3085, IC-7300=3073, FT-891=1036")
            print()
            model = input("Enter hamlib model number: ").strip()
            if model:
                config.radio_model = model
                config.radio_model_name = f"Hamlib model {model}"
                success(f"Selected: {config.radio_model_name}")
                return
            continue

        try:
            idx = int(choice)
            if 1 <= idx <= len(RADIO_MODELS):
                config.radio_model = RADIO_MODELS[idx - 1][0]
                config.radio_model_name = RADIO_MODELS[idx - 1][1]
                success(f"Selected: {config.radio_model_name} (model {config.radio_model})")
                return
        except ValueError:
            pass

        warn("Invalid choice")


def detect_audio_devices(config):
    """Detect and select audio devices."""
    header("Audio Device Selection")

    print("Detecting audio devices...")
    print()

    devices = []

    # Try freedvtnc2 first (more accurate for our use case)
    freedvtnc2_cmd = 'freedvtnc2.exe' if IS_WINDOWS else 'freedvtnc2'
    if shutil.which(freedvtnc2_cmd):
        try:
            result = subprocess.run(
                [freedvtnc2_cmd, '--list-audio-devices'],
                capture_output=True, text=True, timeout=10
            )
            print(f"{BOLD}Audio devices (as seen by freedvtnc2):{NC}")
            print()
            for line in result.stdout.splitlines():
                if line.strip() and not line.startswith('ALSA lib'):
                    print(f"  {line}")
            print()
            print(f"{YELLOW}Tip:{NC} Look for your radio's USB audio interface.")
            print("     Choose a device with In > 0 for input, Out > 0 for output.")
            print()
        except Exception:
            pass
    elif HAS_SOUNDDEVICE:
        # Fallback to sounddevice
        print(f"{BOLD}Audio devices:{NC}")
        print()
        try:
            device_list = sd.query_devices()
            for i, dev in enumerate(device_list):
                ins = dev.get('max_input_channels', 0)
                outs = dev.get('max_output_channels', 0)
                name = dev.get('name', 'Unknown')
                print(f"  {BOLD}{i:3}{NC}  {name:<50} In:{ins} Out:{outs}")
            print()
        except Exception as e:
            warn(f"Could not list audio devices: {e}")
    else:
        warn("Neither freedvtnc2 nor sounddevice available for audio detection.")
        print("Install sounddevice with: pip install sounddevice")
        print()

    # Input device selection
    print("Select the audio INPUT device (from radio to computer):")
    print()

    while True:
        choice = input("Enter input device ID: ").strip()
        if choice.isdigit():
            config.audio_input = choice
            success(f"Input device: {choice}")
            break
        warn("Please enter a number")

    # Output device selection
    print()
    print("Select the audio OUTPUT device (from computer to radio):")
    print()

    while True:
        choice = input("Enter output device ID (or 'same' for same as input): ").strip()
        if choice.lower() == 'same':
            config.audio_output = config.audio_input
            success(f"Output device: {config.audio_output} (same as input)")
            break
        elif choice.isdigit():
            config.audio_output = choice
            success(f"Output device: {choice}")
            break
        warn("Please enter a number or 'same'")


def select_ptt_method(config):
    """Select PTT method."""
    header("PTT Method Selection")

    if config.radio_serial == 'none':
        config.ptt_method = 'none'
        info("Using VOX (no PTT control)")
        return

    print("How should PTT (Push-to-Talk) be controlled?")
    print()
    print(f"  {BOLD}[1]{NC} CAT command via rigctld {GREEN}(Recommended){NC}")
    print("      Works with most modern radios")
    print()
    print(f"  {BOLD}[2]{NC} RTS (Request To Send) pin")
    print("      Hardware PTT via serial port RTS line")
    print()
    print(f"  {BOLD}[3]{NC} DTR (Data Terminal Ready) pin")
    print("      Hardware PTT via serial port DTR line")
    print()
    print(f"  {BOLD}[4]{NC} VOX (Voice Operated Switch)")
    print("      Radio triggers on audio, no PTT signal")
    print()

    while True:
        choice = input("Select PTT method [1-4]: ").strip()

        if choice == '1':
            config.ptt_method = 'rigctld'
            success("PTT method: CAT via rigctld")
            return
        elif choice == '2':
            config.ptt_method = 'RTS'
            success("PTT method: RTS")
            return
        elif choice == '3':
            config.ptt_method = 'DTR'
            success("PTT method: DTR")
            return
        elif choice == '4':
            config.ptt_method = 'none'
            success("PTT method: VOX (none)")
            return

        warn("Invalid choice")


def select_freedv_mode(config):
    """Select FreeDV data mode."""
    header("FreeDV Mode Selection")

    print("Select the FreeDV data mode:")
    print()
    print(f"  {BOLD}[1]{NC} DATAC1 {GREEN}(Recommended for HF){NC}")
    print("      980 bps, robust, works down to 5dB SNR")
    print()
    print(f"  {BOLD}[2]{NC} DATAC3")
    print("      Faster, but needs better conditions")
    print()
    print(f"  {BOLD}[3]{NC} DATAC4")
    print("      Best for poor conditions, works down to -8dB SNR")
    print()

    while True:
        choice = input("Select FreeDV mode [1-3]: ").strip()

        if choice == '1':
            config.freedv_mode = 'DATAC1'
            success("FreeDV mode: DATAC1")
            return
        elif choice == '2':
            config.freedv_mode = 'DATAC3'
            success("FreeDV mode: DATAC3")
            return
        elif choice == '3':
            config.freedv_mode = 'DATAC4'
            success("FreeDV mode: DATAC4")
            return

        warn("Invalid choice")


def generate_configs(config):
    """Generate all configuration files."""
    header("Generating Configuration")

    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)

    # Master config file
    config_file = config_dir / 'config'
    info("Writing master config...")

    config_content = f"""# hf-nomad configuration
# Generated: {datetime.now().isoformat()}

# Radio settings
RADIO_SERIAL="{config.radio_serial}"
RADIO_MODEL="{config.radio_model}"
RADIO_MODEL_NAME="{config.radio_model_name}"

# Audio settings
AUDIO_INPUT_DEVICE="{config.audio_input}"
AUDIO_OUTPUT_DEVICE="{config.audio_output}"

# FreeDV settings
FREEDV_MODE="{config.freedv_mode}"

# PTT settings
PTT_METHOD="{config.ptt_method}"

# Network ports
RIGCTLD_PORT="{config.rigctld_port}"
KISS_PORT="{config.kiss_port}"
"""
    config_file.write_text(config_content)
    success(f"Created: {config_file}")

    # Also write as JSON for easier Python parsing
    json_file = config_dir / 'config.json'
    json_content = {
        'radio_serial': config.radio_serial,
        'radio_model': config.radio_model,
        'radio_model_name': config.radio_model_name,
        'audio_input': config.audio_input,
        'audio_output': config.audio_output,
        'freedv_mode': config.freedv_mode,
        'ptt_method': config.ptt_method,
        'rigctld_port': config.rigctld_port,
        'kiss_port': config.kiss_port,
    }
    json_file.write_text(json.dumps(json_content, indent=2))
    success(f"Created: {json_file}")

    # freedvtnc2 config
    freedvtnc2_config = get_freedvtnc2_config_path()
    if confirm_overwrite(freedvtnc2_config, "freedvtnc2"):
        freedvtnc2_config.parent.mkdir(parents=True, exist_ok=True)

        freedv_content = f"""# freedvtnc2 configuration
# Generated by hf-nomad

input-device={config.audio_input}
output-device={config.audio_output}
mode={config.freedv_mode}
kiss-tcp-port={config.kiss_port}
kiss-tcp-address=127.0.0.1
"""

        if config.ptt_method == 'rigctld':
            freedv_content += f"""ptt-method=rigctld
rigctld-host=localhost
rigctld-port={config.rigctld_port}
"""
        elif config.ptt_method in ('RTS', 'DTR'):
            freedv_content += f"""ptt-method={config.ptt_method}
ptt-device={config.radio_serial}
"""

        freedvtnc2_config.write_text(freedv_content)
        success(f"Created: {freedvtnc2_config}")

    # Reticulum config - add HF interface
    reti_config = get_reticulum_config_path()
    hf_interface_block = f"""
  [[HF Radio via FreeDV]]
    type = TCPClientInterface
    enabled = yes
    kiss_framing = True
    target_host = 127.0.0.1
    target_port = {config.kiss_port}
"""

    if reti_config.exists():
        content = reti_config.read_text()
        if 'HF Radio via FreeDV' in content:
            info("Reticulum HF interface already configured")
        else:
            info("Adding HF interface to existing Reticulum config...")
            backup = reti_config.with_suffix(f'.backup.{datetime.now().strftime("%Y%m%d%H%M%S")}')
            shutil.copy(reti_config, backup)
            with open(reti_config, 'a') as f:
                f.write(hf_interface_block)
            success(f"Added HF interface to: {reti_config}")
    else:
        # Try to generate default config
        info("No Reticulum config found. Generating default config...")
        reti_config.parent.mkdir(parents=True, exist_ok=True)

        rnsd_cmd = 'rnsd.exe' if IS_WINDOWS else 'rnsd'
        if shutil.which(rnsd_cmd):
            try:
                subprocess.run([rnsd_cmd], timeout=2)
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        if reti_config.exists():
            with open(reti_config, 'a') as f:
                f.write(hf_interface_block)
            success("Generated default config and added HF interface")
        else:
            warn("Could not generate Reticulum config")
            print()
            print("Please run 'nomadnet' once to generate the default config,")
            print("then run this configure script again to add the HF interface.")
            print()

    info("NomadNet will use default configuration")


def print_summary(config):
    """Print configuration summary."""
    print()
    print(f"{GREEN}============================================{NC}")
    print(f"{GREEN} Configuration Complete!{NC}")
    print(f"{GREEN}============================================{NC}")
    print()
    print("Configuration summary:")
    print(f"  Radio:      {config.radio_model_name}")
    print(f"  Serial:     {config.radio_serial}")
    print(f"  Audio In:   Device {config.audio_input}")
    print(f"  Audio Out:  Device {config.audio_output}")
    print(f"  PTT:        {config.ptt_method}")
    print(f"  FreeDV:     {config.freedv_mode}")
    print()
    print("Config files:")
    print(f"  {get_config_dir() / 'config'}")
    print(f"  {get_freedvtnc2_config_path()}")
    print(f"  {get_reticulum_config_path()} (HF interface added)")
    print()
    print(f"{BOLD}Quick Start:{NC}")
    print()
    if IS_WINDOWS:
        print("  python hf_nomad.py start    # Start the HF radio stack")
        print("  python hf_nomad.py status   # Check status")
        print("  nomadnet                    # Launch NomadNet")
    else:
        print("  hf-nomad start       # Start the HF radio stack")
        print("  hf-nomad status      # Check status")
        print("  nomadnet             # Launch NomadNet")
    print()
    print(f"{BOLD}Other Commands:{NC}")
    print()
    if IS_WINDOWS:
        print("  python hf_nomad.py test-radio  # Test CAT connection")
        print("  python hf_nomad.py test-audio  # Test audio devices")
        print("  python hf_nomad.py stop        # Stop all services")
    else:
        print("  hf-nomad test-radio  # Test CAT connection")
        print("  hf-nomad test-audio  # Test audio devices")
        print("  hf-nomad stop        # Stop all services")
    print()


def main():
    print()
    print(f"{BLUE}======================================{NC}")
    print(f"{BLUE} hf-nomad Configuration Wizard{NC}")
    print(f"{BLUE}======================================{NC}")

    platform_name = "Windows" if IS_WINDOWS else "Linux" if IS_LINUX else sys.platform
    info(f"Platform: {platform_name}")

    config = Config()

    detect_serial_ports(config)
    select_radio_model(config)
    detect_audio_devices(config)
    select_ptt_method(config)
    select_freedv_mode(config)
    generate_configs(config)
    print_summary(config)


if __name__ == '__main__':
    main()
