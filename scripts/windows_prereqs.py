#!/usr/bin/env python3
"""
Windows Prerequisites Checker/Installer for hf-nomad
Run this BEFORE windows_setup.py to ensure all prerequisites are met.

Prerequisites:
1. Python 3.11+ from python.org (NOT Microsoft Store)
2. Visual Studio Build Tools 2022 (for MSVC compiler)
3. MSYS2 with codec2 built

Can auto-install missing prerequisites using winget (Windows 10/11).
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from urllib.request import urlretrieve
import tempfile


def has_winget():
    """Check if winget is available."""
    try:
        result = subprocess.run(['winget', '--version'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def install_with_winget(package_id, package_name):
    """Install a package using winget."""
    print(f"  Installing {package_name} via winget...")
    print(f"  This may take several minutes and require admin approval.")
    print()
    result = subprocess.run(['winget', 'install', '--id', package_id, '-e', '--accept-source-agreements', '--accept-package-agreements'],
                           capture_output=False)
    return result.returncode == 0

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
    print(f"{RED}[FAIL]{NC} {msg}")


def check_python():
    """Check Python version and installation source."""
    print()
    print(f"{BOLD}Checking Python...{NC}")

    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        fail(f"Python 3.11+ required, found {version.major}.{version.minor}")
        return False

    success(f"Python {version.major}.{version.minor}.{version.micro}")

    # Check if it's Microsoft Store version (problematic)
    exe_path = sys.executable
    if 'WindowsApps' in exe_path:
        warn("Microsoft Store Python detected - may cause issues")
        warn("Recommend installing from https://www.python.org/downloads/")
        return False

    success(f"Installation: {exe_path}")
    return True


def check_vs_build_tools(offer_install=True):
    """Check for Visual Studio Build Tools with MSVC."""
    print()
    print(f"{BOLD}Checking Visual Studio Build Tools...{NC}")

    # Look for lib.exe (needed to create import libraries)
    vs_paths = [
        Path('C:/Program Files (x86)/Microsoft Visual Studio'),
        Path('C:/Program Files/Microsoft Visual Studio'),
    ]

    lib_exe = None
    for vs_base in vs_paths:
        if vs_base.exists():
            for lib_path in vs_base.rglob('lib.exe'):
                if 'x64' in str(lib_path).lower():
                    lib_exe = lib_path
                    break

    if lib_exe:
        success(f"Found MSVC lib.exe: {lib_exe}")
        return True

    fail("Visual Studio Build Tools not found")
    print()

    if offer_install and has_winget():
        print("  Visual Studio Build Tools can be installed automatically.")
        response = input("  Install via winget? [y/N]: ").strip().lower()
        if response == 'y':
            # Install VS Build Tools with C++ workload
            print()
            info("Installing Visual Studio Build Tools...")
            info("This is a large download (~2GB) and may take 10-20 minutes.")
            result = subprocess.run([
                'winget', 'install',
                '--id', 'Microsoft.VisualStudio.2022.BuildTools',
                '-e', '--accept-source-agreements', '--accept-package-agreements',
                '--override', '--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --quiet --wait'
            ], capture_output=False)
            if result.returncode == 0:
                success("VS Build Tools installed! Restart this script to verify.")
                return False  # Need restart to detect
            else:
                warn("Installation may have failed. Try manual install.")

    print("  To install manually:")
    print("  1. Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/")
    print("  2. Run installer")
    print("  3. Select 'Desktop development with C++'")
    print("  4. Install and restart this script")
    return False


def check_msys2(offer_install=True):
    """Check for MSYS2 installation."""
    print()
    print(f"{BOLD}Checking MSYS2...{NC}")

    msys_paths = [
        Path('C:/msys64'),
        Path('C:/msys32'),
    ]

    for msys in msys_paths:
        if msys.exists():
            mingw_bin = msys / 'mingw64' / 'bin'
            if mingw_bin.exists():
                success(f"Found MSYS2: {msys}")
                return msys

    fail("MSYS2 not found")
    print()

    if offer_install and has_winget():
        print("  MSYS2 can be installed automatically.")
        response = input("  Install via winget? [y/N]: ").strip().lower()
        if response == 'y':
            print()
            info("Installing MSYS2...")
            result = subprocess.run([
                'winget', 'install', '--id', 'MSYS2.MSYS2',
                '-e', '--accept-source-agreements', '--accept-package-agreements'
            ], capture_output=False)
            if result.returncode == 0:
                success("MSYS2 installed!")
                print()
                info("Now installing required MSYS2 packages...")
                # Run pacman to install toolchain
                msys_path = Path('C:/msys64')
                if msys_path.exists():
                    install_msys2_packages(msys_path)
                    return msys_path
            else:
                warn("Installation may have failed. Try manual install.")

    print("  To install manually:")
    print("  1. Download from: https://www.msys2.org/")
    print("  2. Run installer (use default C:\\msys64)")
    print("  3. Open MINGW64 terminal (not MSYS2 MSYS)")
    print("  4. Run: pacman -Syu")
    print("  5. Run: pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja git")
    return None


def install_msys2_packages(msys_path):
    """Install required packages in MSYS2."""
    info("Installing MSYS2 toolchain packages...")
    print("  This may open an MSYS2 window.")

    # Create a script to run in MSYS2
    # Note: ninja is the default cmake generator on MSYS2, so we include it
    script = """#!/bin/bash
pacman -Syu --noconfirm
pacman -S --noconfirm mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja git
"""
    script_path = msys_path / 'tmp' / 'install_packages.sh'
    script_path.write_text(script.replace('\r\n', '\n'))

    # Run via MSYS2 bash
    bash_exe = msys_path / 'usr' / 'bin' / 'bash.exe'
    if bash_exe.exists():
        result = subprocess.run([str(bash_exe), '-l', '-c', '/tmp/install_packages.sh'],
                               capture_output=False, timeout=600)
        if result.returncode == 0:
            success("MSYS2 packages installed!")
        else:
            warn("Package installation may have failed.")


def check_codec2(msys_path):
    """Check if codec2 is built in MSYS2."""
    print()
    print(f"{BOLD}Checking codec2...{NC}")

    if not msys_path:
        fail("Cannot check codec2 - MSYS2 not found")
        return None

    # Search for codec2 build
    for codec2_src in msys_path.rglob('codec2/src/freedv_api.h'):
        src_dir = codec2_src.parent
        build_dir = src_dir.parent / 'build' / 'src'
        dll = build_dir / 'libcodec2.dll'

        if dll.exists():
            success(f"Found codec2 source: {src_dir}")
            success(f"Found codec2 DLL: {dll}")
            return {
                'include': str(src_dir),
                'lib': str(build_dir),
                'dll': str(dll),
            }

    fail("codec2 not built")
    print()
    print("  To build codec2:")
    print("  1. Open MSYS2 MINGW64 terminal")
    print("  2. Run these commands:")
    print()
    print(f"     cd ~")
    print(f"     git clone https://github.com/drowe67/codec2.git")
    print(f"     cd codec2")
    print(f"     mkdir build && cd build")
    print(f"     cmake ..")
    print(f"     make")
    print()
    print("  3. Re-run this script to verify")
    return None


def check_mingw_dlls(msys_path):
    """Check for required MinGW runtime DLLs."""
    print()
    print(f"{BOLD}Checking MinGW runtime DLLs...{NC}")

    if not msys_path:
        fail("Cannot check DLLs - MSYS2 not found")
        return False

    mingw_bin = msys_path / 'mingw64' / 'bin'
    required_dlls = ['libgcc_s_seh-1.dll', 'libwinpthread-1.dll']

    all_found = True
    for dll_name in required_dlls:
        dll = mingw_bin / dll_name
        if dll.exists():
            success(f"Found {dll_name}")
        else:
            fail(f"Missing {dll_name}")
            all_found = False

    if not all_found:
        print()
        print("  MinGW runtime DLLs missing from MSYS2.")
        print("  Open MSYS2 MINGW64 and run:")
        print("    pacman -S mingw-w64-x86_64-gcc")

    return all_found


def offer_auto_build_codec2(msys_path):
    """Offer to automatically build codec2."""
    print()
    print(f"{BOLD}Would you like to automatically build codec2?{NC}")
    print("This will run commands in MSYS2 MINGW64 shell.")
    print()

    response = input("Build codec2 now? [y/N]: ").strip().lower()
    if response != 'y':
        return False

    # Create a batch script that runs in MSYS2
    # Note: MSYS2 uses ninja by default, not make
    script_content = """#!/bin/bash
set -e
echo "Building codec2..."
cd ~
if [ ! -d "codec2" ]; then
    git clone https://github.com/drowe67/codec2.git
fi
cd codec2
mkdir -p build
cd build
cmake ..
ninja
echo "codec2 build complete!"
"""

    script_path = msys_path / 'tmp' / 'build_codec2.sh'
    script_path.write_text(script_content.replace('\r\n', '\n'))

    # Run via MSYS2
    msys_exe = msys_path / 'msys2_shell.cmd'

    info("Starting codec2 build in MSYS2...")
    print("(This will open a new window - wait for it to complete)")
    print()

    try:
        # Run in MINGW64 environment
        result = subprocess.run(
            [str(msys_exe), '-mingw64', '-defterm', '-no-start', '-c', '/tmp/build_codec2.sh'],
            cwd=str(msys_path),
            timeout=600  # 10 minute timeout
        )

        if result.returncode == 0:
            success("codec2 build completed!")
            return True
        else:
            fail("codec2 build failed")
            return False

    except subprocess.TimeoutExpired:
        fail("Build timed out")
        return False
    except Exception as e:
        fail(f"Build failed: {e}")
        return False


def print_summary(results):
    """Print summary of all checks."""
    print()
    print("=" * 50)
    print(f"{BOLD}Prerequisites Summary{NC}")
    print("=" * 50)
    print()

    all_pass = True

    checks = [
        ('Python 3.11+', results.get('python', False)),
        ('VS Build Tools', results.get('vs_build_tools', False)),
        ('MSYS2', results.get('msys2', False)),
        ('codec2 built', results.get('codec2', False)),
        ('MinGW DLLs', results.get('mingw_dlls', False)),
    ]

    for name, passed in checks:
        if passed:
            print(f"  {GREEN}[PASS]{NC} {name}")
        else:
            print(f"  {RED}[FAIL]{NC} {name}")
            all_pass = False

    print()

    if all_pass:
        print(f"{GREEN}All prerequisites met!{NC}")
        print()
        print("You can now run:")
        print(f"  python scripts/windows_setup.py")
        print()
    else:
        print(f"{RED}Some prerequisites are missing.{NC}")
        print()
        print("Please install the missing components and run this script again.")
        print()

    return all_pass


def main():
    print()
    print(f"{BOLD}=== hf-nomad Windows Prerequisites Checker ==={NC}")
    print()
    print("This script checks that all prerequisites are installed")
    print("before running the main Windows setup.")
    print()

    # Check for winget
    if has_winget():
        success("winget available - can auto-install missing prerequisites")
    else:
        warn("winget not found - manual installation required for missing items")
        print("  (winget comes with Windows 10/11 App Installer)")

    results = {}

    # Check Python
    results['python'] = check_python()

    # Check Visual Studio Build Tools
    results['vs_build_tools'] = check_vs_build_tools()

    # Check MSYS2
    msys_path = check_msys2()
    results['msys2'] = msys_path is not None

    # Check codec2
    codec2_info = check_codec2(msys_path)
    results['codec2'] = codec2_info is not None

    # If codec2 not found, offer to build it
    if not results['codec2'] and results['msys2']:
        if offer_auto_build_codec2(msys_path):
            # Re-check codec2
            codec2_info = check_codec2(msys_path)
            results['codec2'] = codec2_info is not None

    # Check MinGW DLLs
    results['mingw_dlls'] = check_mingw_dlls(msys_path)

    # Print summary
    all_pass = print_summary(results)

    sys.exit(0 if all_pass else 1)


if __name__ == '__main__':
    main()
