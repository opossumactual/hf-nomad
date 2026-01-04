#!/usr/bin/env python3
"""
hf-nomad launcher v0.1.0
Cross-platform process management for HF radio stack
"""

import os
import sys
import json
import signal
import shutil
import subprocess
import time
from pathlib import Path

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')

# ANSI colors
if IS_WINDOWS:
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
    BOLD = '\033[1m'
    NC = '\033[0m'
else:
    RED = GREEN = YELLOW = BLUE = BOLD = NC = ''


def info(msg):
    print(f"{BLUE}[INFO]{NC} {msg}")

def success(msg):
    print(f"{GREEN}[OK]{NC} {msg}")

def warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")

def error(msg, exit_code=1):
    print(f"{RED}[ERROR]{NC} {msg}")
    if exit_code:
        sys.exit(exit_code)


def get_config_dir():
    """Get platform-appropriate config directory."""
    if IS_WINDOWS:
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
        return Path(base) / 'hf-nomad'
    else:
        return Path.home() / '.config' / 'hf-nomad'


def load_config():
    """Load configuration from JSON file."""
    config_file = get_config_dir() / 'config.json'
    if not config_file.exists():
        error(f"Config not found: {config_file}\nRun 'python configure.py' first.")
    return json.loads(config_file.read_text())


def get_state_file():
    """Get path to state file tracking running processes."""
    return get_config_dir() / 'running.json'


def save_state(state):
    """Save process state to file."""
    get_state_file().write_text(json.dumps(state, indent=2))


def load_state():
    """Load process state from file."""
    state_file = get_state_file()
    if state_file.exists():
        try:
            return json.loads(state_file.read_text())
        except Exception:
            pass
    return {}


def clear_state():
    """Clear the state file."""
    state_file = get_state_file()
    if state_file.exists():
        state_file.unlink()


def is_process_running(pid):
    """Check if a process is still running."""
    if pid is None:
        return False
    try:
        if IS_WINDOWS:
            # Windows: use tasklist
            result = subprocess.run(
                ['tasklist', '/FI', f'PID eq {pid}', '/NH'],
                capture_output=True, text=True
            )
            return str(pid) in result.stdout
        else:
            # Unix: send signal 0 to check if process exists
            os.kill(pid, 0)
            return True
    except (OSError, subprocess.SubprocessError):
        return False


def kill_process(pid, name="process"):
    """Kill a process by PID."""
    if not is_process_running(pid):
        return True

    try:
        if IS_WINDOWS:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
            # Wait a bit for graceful shutdown
            for _ in range(10):
                time.sleep(0.2)
                if not is_process_running(pid):
                    return True
            # Force kill if still running
            os.kill(pid, signal.SIGKILL)
        return True
    except Exception as e:
        warn(f"Could not kill {name} (PID {pid}): {e}")
        return False


def find_executable(name):
    """Find an executable, checking common locations."""
    # Add .exe suffix on Windows
    if IS_WINDOWS and not name.endswith('.exe'):
        name_exe = name + '.exe'
    else:
        name_exe = name

    # Check PATH first
    path = shutil.which(name_exe)
    if path:
        return path

    # Check common locations
    if IS_WINDOWS:
        # Find hamlib in user directory (common extraction location)
        hamlib_dirs = list(Path.home().glob('hamlib/hamlib-w64-*/bin'))
        hamlib_dirs += list(Path.home().glob('hamlib/bin'))

        locations = [
            *[d / name_exe for d in hamlib_dirs],
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'hamlib' / 'bin' / name_exe,
            Path('C:/Program Files/hamlib/bin') / name_exe,
            Path('C:/Program Files (x86)/hamlib/bin') / name_exe,
            Path('C:/hamlib/bin') / name_exe,
            # Python Scripts directory for freedvtnc2
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'Python' / 'Python311' / 'Scripts' / name_exe,
            Path.home() / 'AppData' / 'Local' / 'Programs' / 'Python' / 'Python311' / 'Scripts' / name_exe,
        ]
    else:
        locations = [
            Path.home() / '.local' / 'bin' / name,
            Path('/usr/local/bin') / name,
            Path('/usr/bin') / name,
        ]

    for loc in locations:
        if loc.exists():
            return str(loc)

    return None


def cmd_start():
    """Start the HF radio stack."""
    config = load_config()
    state = load_state()

    # Check if already running
    if state.get('rigctld_pid') and is_process_running(state['rigctld_pid']):
        warn("rigctld already running")
    if state.get('freedvtnc2_pid') and is_process_running(state['freedvtnc2_pid']):
        warn("freedvtnc2 already running")
        return

    new_state = {}

    # Start rigctld if using CAT control
    if config['ptt_method'] == 'rigctld' and config['radio_serial'] != 'none':
        rigctld = find_executable('rigctld')
        if not rigctld:
            error("rigctld not found. Make sure hamlib is installed and in PATH.")

        info(f"Starting rigctld for {config['radio_model_name']}...")

        rigctld_args = [
            rigctld,
            '-m', config['radio_model'],
            '-r', config['radio_serial'],
            '-t', config['rigctld_port'],
        ]

        try:
            if IS_WINDOWS:
                # Windows: use CREATE_NEW_PROCESS_GROUP to allow clean shutdown
                proc = subprocess.Popen(
                    rigctld_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                proc = subprocess.Popen(
                    rigctld_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )

            new_state['rigctld_pid'] = proc.pid
            time.sleep(1)  # Give rigctld time to start

            if is_process_running(proc.pid):
                success(f"rigctld started (PID {proc.pid})")
            else:
                error("rigctld failed to start", exit_code=0)

        except Exception as e:
            error(f"Failed to start rigctld: {e}", exit_code=0)

    # Start freedvtnc2
    info("Starting freedvtnc2...")

    try:
        if IS_WINDOWS:
            # On Windows, run as python module to avoid .exe wrapper issues
            proc = subprocess.Popen(
                [sys.executable, '-m', 'freedvtnc2', '--no-cli'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            freedvtnc2 = find_executable('freedvtnc2')
            if not freedvtnc2:
                error("freedvtnc2 not found. Make sure it's installed via pip/pipx.")
            proc = subprocess.Popen(
                [freedvtnc2],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )

        new_state['freedvtnc2_pid'] = proc.pid
        time.sleep(1)

        if is_process_running(proc.pid):
            success(f"freedvtnc2 started (PID {proc.pid})")
        else:
            error("freedvtnc2 failed to start", exit_code=0)

    except Exception as e:
        error(f"Failed to start freedvtnc2: {e}", exit_code=0)

    save_state(new_state)

    print()
    success("HF radio stack started!")
    print()
    print("KISS TCP interface available at: 127.0.0.1:" + config['kiss_port'])
    print()
    print("You can now run: nomadnet")
    print()


def cmd_stop():
    """Stop all running processes."""
    state = load_state()

    if not state:
        info("Nothing running")
        return

    stopped = False

    if state.get('freedvtnc2_pid'):
        info("Stopping freedvtnc2...")
        if kill_process(state['freedvtnc2_pid'], 'freedvtnc2'):
            success("freedvtnc2 stopped")
            stopped = True

    if state.get('rigctld_pid'):
        info("Stopping rigctld...")
        if kill_process(state['rigctld_pid'], 'rigctld'):
            success("rigctld stopped")
            stopped = True

    clear_state()

    if stopped:
        print()
        success("HF radio stack stopped")


def cmd_status():
    """Show status of running processes."""
    state = load_state()
    config = None

    try:
        config = load_config()
    except SystemExit:
        pass

    print()
    print(f"{BOLD}hf-nomad status{NC}")
    print()

    # rigctld status
    rigctld_pid = state.get('rigctld_pid')
    if rigctld_pid and is_process_running(rigctld_pid):
        print(f"  rigctld:    {GREEN}running{NC} (PID {rigctld_pid})")
    elif rigctld_pid:
        print(f"  rigctld:    {RED}dead{NC} (was PID {rigctld_pid})")
    else:
        print(f"  rigctld:    {YELLOW}not started{NC}")

    # freedvtnc2 status
    freedvtnc2_pid = state.get('freedvtnc2_pid')
    if freedvtnc2_pid and is_process_running(freedvtnc2_pid):
        print(f"  freedvtnc2: {GREEN}running{NC} (PID {freedvtnc2_pid})")
    elif freedvtnc2_pid:
        print(f"  freedvtnc2: {RED}dead{NC} (was PID {freedvtnc2_pid})")
    else:
        print(f"  freedvtnc2: {YELLOW}not started{NC}")

    print()

    if config:
        print(f"{BOLD}Configuration:{NC}")
        print(f"  Radio:      {config.get('radio_model_name', 'Not set')}")
        print(f"  Serial:     {config.get('radio_serial', 'Not set')}")
        print(f"  FreeDV:     {config.get('freedv_mode', 'Not set')}")
        print(f"  KISS port:  {config.get('kiss_port', '8001')}")
        print()


def cmd_test_radio():
    """Test CAT connection to radio."""
    config = load_config()

    if config['radio_serial'] == 'none':
        warn("No radio configured (VOX mode)")
        return

    rigctl = find_executable('rigctl')
    if not rigctl:
        error("rigctl not found. Make sure hamlib is installed and in PATH.")

    info(f"Testing connection to {config['radio_model_name']}...")
    print(f"  Serial: {config['radio_serial']}")
    print(f"  Model:  {config['radio_model']}")
    print()

    try:
        # Try to get frequency
        result = subprocess.run(
            [rigctl, '-m', config['radio_model'], '-r', config['radio_serial'], 'f'],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0:
            freq = result.stdout.strip()
            success(f"Radio connected! Current frequency: {freq} Hz")
        else:
            error(f"Could not connect: {result.stderr.strip()}", exit_code=0)

    except subprocess.TimeoutExpired:
        error("Connection timed out", exit_code=0)
    except Exception as e:
        error(f"Test failed: {e}", exit_code=0)


def cmd_test_audio():
    """Test audio devices."""
    freedvtnc2 = find_executable('freedvtnc2')

    if freedvtnc2:
        info("Audio devices (via freedvtnc2):")
        print()
        subprocess.run([freedvtnc2, '--list-audio-devices'])
    else:
        try:
            import sounddevice as sd
            info("Audio devices (via sounddevice):")
            print()
            print(sd.query_devices())
        except ImportError:
            error("Neither freedvtnc2 nor sounddevice available.\nInstall with: pip install sounddevice")


def cmd_monitor():
    """Monitor running processes (show live output)."""
    state = load_state()

    if not state.get('freedvtnc2_pid') or not is_process_running(state['freedvtnc2_pid']):
        error("freedvtnc2 is not running. Start with: hf_nomad.py start")

    info("Monitoring is not fully implemented in cross-platform version.")
    info("Use 'hf_nomad.py status' to check process status.")
    print()
    print("Tip: Run freedvtnc2 in foreground to see output:")
    print("  1. hf_nomad.py stop")
    print("  2. freedvtnc2  (in this terminal)")
    print()


def cmd_help():
    """Show help message."""
    script_name = "python hf_nomad.py" if IS_WINDOWS else "hf-nomad"

    print()
    print(f"{BOLD}hf-nomad - HF Radio Stack Manager{NC}")
    print()
    print(f"Usage: {script_name} <command>")
    print()
    print("Commands:")
    print(f"  {BOLD}start{NC}       Start rigctld and freedvtnc2")
    print(f"  {BOLD}stop{NC}        Stop all running processes")
    print(f"  {BOLD}status{NC}      Show status of all processes")
    print(f"  {BOLD}test-radio{NC}  Test CAT connection to radio")
    print(f"  {BOLD}test-audio{NC}  List available audio devices")
    print(f"  {BOLD}monitor{NC}     Monitor process output")
    print(f"  {BOLD}help{NC}        Show this help message")
    print()
    print("Configuration:")
    print(f"  Run 'python configure.py' to set up radio and audio.")
    print()


def main():
    if len(sys.argv) < 2:
        cmd_help()
        sys.exit(1)

    command = sys.argv[1].lower().replace('-', '_')

    commands = {
        'start': cmd_start,
        'stop': cmd_stop,
        'status': cmd_status,
        'test_radio': cmd_test_radio,
        'test_audio': cmd_test_audio,
        'monitor': cmd_monitor,
        'help': cmd_help,
    }

    if command in commands:
        commands[command]()
    else:
        error(f"Unknown command: {sys.argv[1]}")
        cmd_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
