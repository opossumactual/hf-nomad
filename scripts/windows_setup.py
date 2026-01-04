#!/usr/bin/env python3
"""
Windows setup script for hf-nomad
Handles freedvtnc2 patching, hamlib installation, and dependency setup
"""

import os
import sys
import shutil
import subprocess
import tempfile
import zipfile
import tarfile
from pathlib import Path
from urllib.request import urlretrieve

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

def error(msg):
    print(f"{RED}[ERROR]{NC} {msg}")
    sys.exit(1)


def run_pip(*args):
    """Run pip with given arguments."""
    subprocess.run([sys.executable, '-m', 'pip'] + list(args), check=True)


def install_basic_dependencies():
    """Install basic Python dependencies."""
    info("Installing basic dependencies...")
    run_pip('install', 'nomadnet', 'pyserial', 'sounddevice', 'pyreadline3', 'pefile')
    success("Basic dependencies installed")


def install_hamlib():
    """Download and install Hamlib."""
    hamlib_dir = Path.home() / 'hamlib'
    hamlib_bin = hamlib_dir / 'hamlib-w64-4.6.2' / 'bin' / 'rigctld.exe'

    if hamlib_bin.exists():
        info(f"Hamlib already installed at {hamlib_dir}")
        return str(hamlib_bin.parent)

    info("Downloading Hamlib...")
    url = 'https://github.com/Hamlib/Hamlib/releases/download/4.6.2/hamlib-w64-4.6.2.zip'
    zip_path = Path(tempfile.gettempdir()) / 'hamlib.zip'

    urlretrieve(url, zip_path)
    success("Downloaded Hamlib")

    info("Extracting Hamlib...")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(hamlib_dir)
    success(f"Hamlib installed to {hamlib_dir}")

    return str(hamlib_bin.parent)


def find_codec2():
    """Find codec2 installation in MSYS2."""
    msys_paths = [
        Path('C:/msys64'),
        Path('C:/msys32'),
    ]

    for msys in msys_paths:
        if not msys.exists():
            continue

        # Search for codec2 build
        for codec2_src in msys.rglob('codec2/src/freedv_api.h'):
            src_dir = codec2_src.parent
            build_dir = src_dir.parent / 'build' / 'src'
            dll = build_dir / 'libcodec2.dll'

            if dll.exists():
                return {
                    'include': str(src_dir),
                    'lib': str(build_dir),
                    'dll': str(dll),
                }

    return None


def create_import_lib(codec2_info):
    """Create MSVC import library from codec2 DLL."""
    import pefile

    dll_path = codec2_info['dll']
    lib_dir = codec2_info['lib']
    def_path = Path(lib_dir) / 'codec2.def'
    lib_path = Path(lib_dir) / 'codec2.lib'

    if lib_path.exists():
        info("codec2.lib already exists")
        return True

    info("Creating import library from codec2 DLL...")

    # Generate .def file
    pe = pefile.PE(dll_path)
    with open(def_path, 'w') as f:
        f.write('LIBRARY libcodec2.dll\nEXPORTS\n')
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    f.write(f'    {exp.name.decode()}\n')

    # Find MSVC lib.exe
    vs_paths = list(Path('C:/Program Files (x86)/Microsoft Visual Studio').rglob('lib.exe'))
    vs_paths = [p for p in vs_paths if 'x64' in str(p)]

    if not vs_paths:
        error("Could not find MSVC lib.exe. Install Visual Studio Build Tools.")

    lib_exe = str(vs_paths[0])

    # Generate .lib
    result = subprocess.run([lib_exe, '/MACHINE:X64', f'/DEF:{def_path}', f'/OUT:{lib_path}'],
                          capture_output=True, text=True)

    if lib_path.exists():
        success("Created codec2.lib")
        return True
    else:
        error(f"Failed to create import library: {result.stderr}")


def download_freedvtnc2_source():
    """Download freedvtnc2 source package."""
    info("Downloading freedvtnc2 source...")
    temp_dir = Path(tempfile.gettempdir()) / 'freedvtnc2_build'
    temp_dir.mkdir(exist_ok=True)

    run_pip('download', 'freedvtnc2', '--no-deps', '--no-binary=:all:', '-d', str(temp_dir))

    # Find and extract tarball
    tarballs = list(temp_dir.glob('freedvtnc2-*.tar.gz'))
    if not tarballs:
        error("Could not download freedvtnc2 source")

    tarball = tarballs[0]
    with tarfile.open(tarball, 'r:gz') as tf:
        tf.extractall(temp_dir)

    source_dirs = list(temp_dir.glob('freedvtnc2-*'))
    source_dirs = [d for d in source_dirs if d.is_dir()]

    if not source_dirs:
        error("Could not extract freedvtnc2 source")

    return source_dirs[0]


def patch_freedvtnc2_source(source_dir, codec2_info):
    """Patch freedvtnc2 source with codec2 paths."""
    info("Patching freedvtnc2 source with codec2 paths...")

    build_file = source_dir / 'freedvtnc2' / 'freedv_build.py'
    content = build_file.read_text()

    # Add Windows codec2 paths
    include_path = codec2_info['include'].replace('\\', '/')
    lib_path = codec2_info['lib'].replace('\\', '/')

    # Find and patch include_dirs
    old_include = 'include_dirs = [ "/usr/include/codec2/", "/usr/local/include/codec2/", "/opt/homebrew/include/codec2/"]'
    new_include = f'include_dirs = [ "/usr/include/codec2/", "/usr/local/include/codec2/", "/opt/homebrew/include/codec2/", "{include_path}"]'

    old_lib = 'library_dirs = ["/lib", "/usr/lib", "/usr/local/lib/", "/opt/homebrew/lib/"]'
    new_lib = f'library_dirs = ["/lib", "/usr/lib", "/usr/local/lib/", "/opt/homebrew/lib/", "{lib_path}"]'

    content = content.replace(old_include, new_include)
    content = content.replace(old_lib, new_lib)

    build_file.write_text(content)
    success("Patched freedv_build.py")


def install_freedvtnc2(source_dir):
    """Install freedvtnc2 from patched source."""
    info("Installing freedvtnc2...")
    run_pip('install', str(source_dir))
    success("freedvtnc2 installed")


def copy_runtime_dlls(codec2_info):
    """Copy runtime DLLs to Python directory."""
    info("Copying runtime DLLs...")

    # Find Python directory
    python_dir = Path(sys.executable).parent

    # Copy codec2 DLL
    dll = Path(codec2_info['dll'])
    shutil.copy(dll, python_dir)
    success(f"Copied {dll.name}")

    # Find and copy MinGW runtime DLLs
    mingw_dlls = ['libgcc_s_seh-1.dll', 'libwinpthread-1.dll']
    mingw_bin = Path('C:/msys64/mingw64/bin')

    for dll_name in mingw_dlls:
        dll = mingw_bin / dll_name
        if dll.exists():
            shutil.copy(dll, python_dir)
            success(f"Copied {dll_name}")
        else:
            warn(f"Could not find {dll_name}")


def patch_installed_freedvtnc2():
    """Patch installed freedvtnc2 for Windows compatibility."""
    info("Patching freedvtnc2 for Windows compatibility...")

    # Find site-packages
    import freedvtnc2
    pkg_dir = Path(freedvtnc2.__file__).parent

    # Patch tnc.py
    tnc_file = pkg_dir / 'tnc.py'
    content = tnc_file.read_text()

    old_imports = '''import kissfix
import os, pty, tty, termios
import threading
import logging
import sys, traceback
import fcntl'''

    new_imports = '''import kissfix
import os
import threading
import logging
import sys, traceback
import platform

# Only import Unix-specific modules on non-Windows platforms
if platform.system() != 'Windows':
    import pty, tty, termios
    import fcntl'''

    if old_imports in content:
        content = content.replace(old_imports, new_imports)
        tnc_file.write_text(content)
        success("Patched tnc.py")
    else:
        info("tnc.py already patched or different version")

    # Patch shell.py
    shell_file = pkg_dir / 'shell.py'
    content = shell_file.read_text()

    if 'import readline' in content and 'pyreadline3' not in content:
        content = content.replace(
            'import readline',
            '''try:
    import readline
except ImportError:
    import pyreadline3 as readline'''
        )
        shell_file.write_text(content)
        success("Patched shell.py")
    else:
        info("shell.py already patched or different version")


def add_to_path():
    """Add Python Scripts to PATH."""
    scripts_dir = Path(sys.executable).parent / 'Scripts'
    python_dir = Path(sys.executable).parent

    current_path = os.environ.get('PATH', '')
    if str(scripts_dir) not in current_path:
        info("Adding Python directories to PATH...")
        # This only affects current session; user needs to add permanently
        os.environ['PATH'] = f"{scripts_dir};{python_dir};{current_path}"
        warn("PATH updated for this session only.")
        print(f"  Add these to your system PATH permanently:")
        print(f"    {scripts_dir}")
        print(f"    {python_dir}")


def test_installation():
    """Test the installation."""
    print()
    info("Testing installation...")

    try:
        from _freedv_cffi import ffi, lib
        version = lib.freedv_get_version()
        success(f"freedvtnc2 working! codec2 version: {version}")
    except Exception as e:
        error(f"freedvtnc2 test failed: {e}")

    # Test hamlib
    hamlib_dir = Path.home() / 'hamlib'
    rigctld = list(hamlib_dir.rglob('rigctld.exe'))
    if rigctld:
        success(f"Hamlib found at {rigctld[0].parent}")
    else:
        warn("Hamlib not found")


def main():
    print()
    print(f"{BOLD}=== hf-nomad Windows Setup ==={NC}")
    print()

    # Check for codec2
    codec2_info = find_codec2()
    if not codec2_info:
        error("""
codec2 not found in MSYS2.

Please build codec2 first:
  1. Install MSYS2 from https://www.msys2.org/
  2. Open MINGW64 terminal
  3. Run: pacman -S mingw-w64-x86_64-toolchain cmake
  4. Clone and build codec2:
     git clone https://github.com/drowe67/codec2.git
     cd codec2 && mkdir build && cd build
     cmake .. && make
""")

    info(f"Found codec2 at {codec2_info['include']}")

    # Step 1: Install basic deps
    install_basic_dependencies()

    # Step 2: Create import library
    create_import_lib(codec2_info)

    # Step 3: Download and patch freedvtnc2
    source_dir = download_freedvtnc2_source()
    patch_freedvtnc2_source(source_dir, codec2_info)

    # Step 4: Install freedvtnc2
    install_freedvtnc2(source_dir)

    # Step 5: Copy runtime DLLs
    copy_runtime_dlls(codec2_info)

    # Step 6: Patch installed freedvtnc2
    patch_installed_freedvtnc2()

    # Step 7: Install hamlib
    install_hamlib()

    # Step 8: Update PATH
    add_to_path()

    # Test
    test_installation()

    print()
    success("Setup complete!")
    print()
    print("Next steps:")
    print("  1. Run: python configure.py")
    print("  2. Run: python hf_nomad.py start")
    print("  3. Run: nomadnet")
    print()


if __name__ == '__main__':
    main()
