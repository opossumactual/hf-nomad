#!/usr/bin/env python3
"""
Windows uninstall script for hf-nomad
Removes hf-nomad components installed by windows_setup.py
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Require Windows
if sys.platform != 'win32':
    print("This script is for Windows only.")
    sys.exit(1)

# ANSI colors
try:
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'
except Exception:
    RED = GREEN = YELLOW = BLUE = BOLD = NC = ''


def info(msg):
    print(f"{BLUE}[INFO]{NC} {msg}")

def success(msg):
    print(f"{GREEN}[OK]{NC} {msg}")

def warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")

def fail(msg):
    print(f"{RED}[ERROR]{NC} {msg}")


def remove_file(path, description):
    """Remove a file if it exists."""
    p = Path(path)
    if p.exists():
        try:
            p.unlink()
            success(f"Removed {description}: {p}")
            return True
        except PermissionError:
            warn(f"Could not remove {description} (in use?): {p}")
            return False
    return False


def remove_dir(path, description):
    """Remove a directory if it exists."""
    p = Path(path)
    if p.exists():
        try:
            shutil.rmtree(p)
            success(f"Removed {description}: {p}")
            return True
        except PermissionError:
            warn(f"Could not remove {description} (in use?): {p}")
            return False
    return False


def uninstall_freedvtnc2():
    """Uninstall freedvtnc2 package."""
    info("Uninstalling freedvtnc2...")
    result = subprocess.run(
        [sys.executable, '-m', 'pip', 'uninstall', 'freedvtnc2', '-y'],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        success("Uninstalled freedvtnc2")
    else:
        warn("freedvtnc2 not installed or already removed")


def remove_runtime_dlls():
    """Remove runtime DLLs from Python directory."""
    python_dir = Path(sys.executable).parent
    dlls = ['libcodec2.dll', 'libgcc_s_seh-1.dll', 'libwinpthread-1.dll']

    for dll in dlls:
        remove_file(python_dir / dll, f"runtime DLL {dll}")


def remove_hf_nomad_command():
    """Remove hf-nomad.cmd from Scripts."""
    scripts_dir = Path(sys.executable).parent / 'Scripts'
    remove_file(scripts_dir / 'hf-nomad.cmd', "hf-nomad command")


def remove_config_files():
    """Remove hf-nomad and freedvtnc2 config files."""
    # hf-nomad config directory
    appdata = os.environ.get('APPDATA', '')
    if appdata:
        remove_dir(Path(appdata) / 'hf-nomad', "hf-nomad config directory")

    # freedvtnc2 config file
    remove_file(Path.home() / '.freedvtnc2.conf', "freedvtnc2 config")


def remove_hamlib():
    """Remove Hamlib installation."""
    hamlib_dir = Path.home() / 'hamlib'
    if hamlib_dir.exists():
        remove_dir(hamlib_dir, "Hamlib")


def stop_running_processes():
    """Stop any running hf-nomad processes."""
    info("Stopping running processes...")

    # Try to use hf_nomad.py stop if available
    hf_nomad_py = Path(__file__).parent.parent / 'hf_nomad.py'
    if hf_nomad_py.exists():
        subprocess.run([sys.executable, str(hf_nomad_py), 'stop'],
                      capture_output=True)

    # Also try to kill by name
    subprocess.run(['taskkill', '/F', '/IM', 'rigctld.exe'],
                  capture_output=True)


def main():
    print()
    print(f"{BOLD}=== hf-nomad Windows Uninstaller ==={NC}")
    print()
    print("This will remove hf-nomad components installed by windows_setup.py")
    print()
    print("Components that will be removed:")
    print("  - freedvtnc2 Python package")
    print("  - Runtime DLLs (libcodec2.dll, etc.) from Python directory")
    print("  - hf-nomad.cmd command")
    print("  - Config files (~/.freedvtnc2.conf, %APPDATA%/hf-nomad/)")
    print()
    print("Components that will NOT be removed:")
    print("  - Python")
    print("  - Visual Studio Build Tools")
    print("  - MSYS2 / codec2 source")
    print("  - nomadnet, reticulum (pip packages)")
    print()

    response = input("Continue with uninstall? [y/N]: ").strip().lower()
    if response != 'y':
        print("Uninstall cancelled.")
        return

    print()

    # Stop running processes first
    stop_running_processes()

    # Uninstall freedvtnc2
    uninstall_freedvtnc2()

    # Remove runtime DLLs
    info("Removing runtime DLLs...")
    remove_runtime_dlls()

    # Remove hf-nomad command
    remove_hf_nomad_command()

    # Remove config files
    info("Removing config files...")
    remove_config_files()

    # Ask about Hamlib
    hamlib_dir = Path.home() / 'hamlib'
    if hamlib_dir.exists():
        print()
        response = input("Also remove Hamlib? [y/N]: ").strip().lower()
        if response == 'y':
            remove_hamlib()

    print()
    success("Uninstall complete!")
    print()
    print("Note: The hf-nomad source directory was not removed.")
    print("You can delete it manually if no longer needed.")
    print()


if __name__ == '__main__':
    main()
