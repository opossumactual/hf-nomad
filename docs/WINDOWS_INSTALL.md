# hf-nomad Windows Installation Guide

This guide covers installing hf-nomad and all dependencies on Windows for running NomadNet/Reticulum over HF radio using FreeDV.

## Why Windows Installation Is Complex

freedvtnc2 was designed for Linux and has several challenges on Windows:

1. **codec2 library dependency**: freedvtnc2 uses CFFI to call the codec2 C library. The build script has hardcoded Unix paths (`/usr/include/codec2/`, `/opt/homebrew/include/codec2/`).

2. **Compiler mismatch**: Python on Windows uses MSVC (Visual Studio), but codec2 is typically built with MinGW/GCC in MSYS2. MSVC can't link MinGW `.a` files - we need to create a `.lib` import library.

3. **Runtime DLL dependencies**: The MinGW-built codec2.dll depends on MinGW runtime DLLs (`libgcc_s_seh-1.dll`, `libwinpthread-1.dll`) that must be in PATH.

4. **Unix-only Python modules**: freedvtnc2 imports `pty`, `tty`, `termios`, and `fcntl` - none of which exist on Windows. The code must be patched to make these conditional.

5. **readline module**: The interactive shell uses `readline` which doesn't exist on Windows - we need `pyreadline3` as a replacement.

**Bottom line**: You can't just `pip install freedvtnc2` on Windows. This guide walks through every workaround.

## Quick Start (Automated)

Run the prerequisites checker first, then the setup script:

```powershell
cd hf-nomad
py -3.11 scripts/windows_prereqs.py   # Check/guide prerequisites
py -3.11 scripts/windows_setup.py     # Automated setup
```

If prerequisites are missing, the checker will guide you through installing them.

---

## Prerequisites

- Windows 10/11 (64-bit)
- Python 3.11 (from python.org - NOT Microsoft Store version)
- MSYS2 with codec2 already built
- Visual Studio Build Tools 2022 (for MSVC compiler and lib.exe)

**Use the prerequisites checker to verify:** `py -3.11 scripts/windows_prereqs.py`

### Building codec2 in MSYS2 (if not already done)

```bash
# In MSYS2 MINGW64 terminal:
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake
git clone https://github.com/drowe67/codec2.git
cd codec2
mkdir build && cd build
cmake ..
make
```

This creates `libcodec2.dll` in `build/src/`.

## Overview

The installation consists of:
1. Installing Python packages (nomadnet, reticulum, etc.)
2. Building/installing freedvtnc2 with codec2 support (the hard part)
3. Installing Hamlib for radio control (rigctld)
4. Patching freedvtnc2 for Windows compatibility

## Step 1: Install Python Packages

```powershell
py -3.11 -m pip install nomadnet pyserial sounddevice pyreadline3
```

## Step 2: Install freedvtnc2 (Complex - requires codec2)

freedvtnc2 requires the codec2 library which must be compiled. If you have codec2 built in MSYS2:

### 2.1 Create MSVC-compatible import library

freedvtnc2 uses CFFI which compiles with MSVC, but codec2 is built with MinGW. We need to create an import library:

```powershell
# Install pefile to parse the DLL
py -3.11 -m pip install pefile

# Generate .def file from DLL exports
py -3.11 -c "
import pefile
dll_path = r'C:\msys64\home\YOUR_USER\codec2\build\src\libcodec2.dll'
def_path = r'C:\msys64\home\YOUR_USER\codec2\build\src\codec2.def'
pe = pefile.PE(dll_path)
with open(def_path, 'w') as f:
    f.write('LIBRARY libcodec2.dll\nEXPORTS\n')
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            f.write(f'    {exp.name.decode()}\n')
print(f'Created {def_path}')
"

# Generate .lib using MSVC lib.exe
py -3.11 -c "
import subprocess
lib_exe = r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\HostX64\x64\lib.exe'
subprocess.run([lib_exe, '/MACHINE:X64',
    '/DEF:C:\\msys64\\home\\YOUR_USER\\codec2\\build\\src\\codec2.def',
    '/OUT:C:\\msys64\\home\\YOUR_USER\\codec2\\build\\src\\codec2.lib'])
"
```

### 2.2 Download and patch freedvtnc2 source

```powershell
# Download source
py -3.11 -m pip download freedvtnc2 --no-deps --no-binary=:all: -d C:\temp\freedvtnc2

# Extract
py -3.11 -c "import tarfile; tarfile.open(r'C:\temp\freedvtnc2\freedvtnc2-0.0.1.tar.gz', 'r:gz').extractall(r'C:\temp\freedvtnc2')"
```

Edit `C:\temp\freedvtnc2\freedvtnc2-0.0.1\freedvtnc2\freedv_build.py`:

Find the `ffibuilder.set_source()` call and add your codec2 paths:

```python
include_dirs = [...existing..., "C:/msys64/home/YOUR_USER/codec2/src"]
library_dirs = [...existing..., "C:/msys64/home/YOUR_USER/codec2/build/src"]
```

### 2.3 Install patched freedvtnc2

```powershell
py -3.11 -m pip install C:\temp\freedvtnc2\freedvtnc2-0.0.1
```

### 2.4 Copy runtime DLLs

Copy these files to your Python directory (e.g., `C:\Users\YOU\AppData\Local\Programs\Python\Python311\`):

From your codec2 build:
- `libcodec2.dll`

From MSYS2 MinGW (`C:\msys64\mingw64\bin\`):
- `libgcc_s_seh-1.dll`
- `libwinpthread-1.dll`

### 2.5 Patch freedvtnc2 for Windows compatibility

**Patch 1: tnc.py** - Make Unix imports conditional

Location: `Lib\site-packages\freedvtnc2\tnc.py`

Change:
```python
import kissfix
import os, pty, tty, termios
import threading
import logging
import sys, traceback
import fcntl
```

To:
```python
import kissfix
import os
import threading
import logging
import sys, traceback
import platform

# Only import Unix-specific modules on non-Windows platforms
if platform.system() != 'Windows':
    import pty, tty, termios
    import fcntl
```

**Patch 2: shell.py** - Handle readline import

Location: `Lib\site-packages\freedvtnc2\shell.py`

Change:
```python
import readline
```

To:
```python
try:
    import readline
except ImportError:
    import pyreadline3 as readline
```

## Step 3: Install Hamlib (for rigctld)

Hamlib provides rigctld for CAT control of your radio.

```powershell
# Download Hamlib
Invoke-WebRequest -Uri 'https://github.com/Hamlib/Hamlib/releases/download/4.6.2/hamlib-w64-4.6.2.zip' -OutFile "$env:USERPROFILE\Downloads\hamlib.zip"

# Extract to user directory
Expand-Archive -Path "$env:USERPROFILE\Downloads\hamlib.zip" -DestinationPath "$env:USERPROFILE\hamlib" -Force
```

Hamlib binaries will be at: `%USERPROFILE%\hamlib\hamlib-w64-4.6.2\bin\`

### Common Radio Model Numbers

| Radio | Hamlib Model |
|-------|--------------|
| Icom IC-705 | 3085 |
| Icom IC-7300 | 3073 |
| Icom IC-7610 | 3078 |
| Yaesu FT-891 | 1036 |
| Yaesu FT-991/991A | 1035 |
| Xiegu G90 | 3088 |

To find your radio: `rigctld.exe -l | findstr "YOUR_RADIO"`

## Step 4: Add Python Scripts to PATH

```powershell
# Add to user PATH permanently
[Environment]::SetEnvironmentVariable('Path',
    [Environment]::GetEnvironmentVariable('Path', 'User') +
    ';C:\Users\YOU\AppData\Local\Programs\Python\Python311\Scripts' +
    ';C:\Users\YOU\AppData\Local\Programs\Python\Python311', 'User')
```

Restart your terminal for PATH changes to take effect.

## Step 5: Configure hf-nomad

```powershell
cd C:\path\to\hf-nomad
py -3.11 configure.py
```

Follow the prompts to set up your radio, audio devices, and PTT method.

## Step 6: Run hf-nomad

```powershell
# Start the HF stack (rigctld + freedvtnc2)
py -3.11 hf_nomad.py start

# Check status
py -3.11 hf_nomad.py status

# Launch NomadNet
nomadnet
```

## Usage Notes

### Serial Ports (COM Ports)

Windows may not auto-detect serial ports in `configure.py`. If no ports are shown, use **Manual entry (M)** and type your COM port (e.g., `COM16`).

Find your COM port in Device Manager under "Ports (COM & LPT)".

### Audio Devices

Windows exposes audio devices through multiple APIs (MME, DirectSound, WASAPI). The same physical device appears multiple times. Generally use the lower-numbered IDs.

List devices with:
```powershell
py -3.11 -m freedvtnc2 --list-audio-devices
```

### Virtual Audio Cables

If using remote radio software (like ICOM RS-BA1), configure:
- RS-BA1 Speaker → Virtual Audio Cable → freedvtnc2 Input
- freedvtnc2 Output → Virtual Audio Cable → RS-BA1 Mic

### PTT Control

- **rigctld (recommended)**: CAT control via serial/USB
- **VOX**: Radio triggers on audio, no PTT signal needed
- Use `--rigctld-port 0` to disable rigctld if using VOX

### KISS TCP Interface

freedvtnc2 provides a KISS TCP interface on `127.0.0.1:8001` by default.

**Do NOT use the `--pts` flag on Windows** - it requires Unix pseudo-terminals.

## Troubleshooting

### "DLL load failed" when importing freedvtnc2

Missing runtime DLLs. Ensure these are in your Python directory:
- `libcodec2.dll`
- `libgcc_s_seh-1.dll`
- `libwinpthread-1.dll`

### "No module named 'termios'"

freedvtnc2 wasn't patched for Windows. Apply the patches in Step 2.5.

### "No module named 'readline'"

Install pyreadline3:
```powershell
py -3.11 -m pip install pyreadline3
```

### rigctld connection refused

rigctld isn't running or wrong port. Check:
```powershell
py -3.11 hf_nomad.py status
```

### freedvtnc2 output buffering

If freedvtnc2 appears to hang with no output, run with unbuffered Python:
```powershell
py -3.11 -u -m freedvtnc2 --input-device X --output-device Y --rigctld-port 0 --no-cli
```

### "fatal error C1083: Cannot open include file: 'freedv_api.h'"

The freedvtnc2 source wasn't patched with your codec2 paths. Edit `freedv_build.py` and add your codec2/src directory to `include_dirs`.

### "LINK : fatal error LNK1181: cannot open input file 'codec2.lib'"

The MSVC import library wasn't created. Follow Step 2.1 to generate `codec2.lib` from the DLL.

### cffi version conflict

If you see `freedvtnc2 requires cffi<2.0.0` but have cffi 2.0.0, it usually still works. The version constraint is overly conservative.

### Audio device issues

Windows shows the same device multiple times (MME, DirectSound, WASAPI). If one doesn't work, try a different ID for the same physical device.

### RS-BA1 / Remote Radio Setup

For ICOM RS-BA1 or similar remote software:
- The radio's virtual audio (ICOM_VAUDIO) may not be the right choice
- Use Virtual Audio Cable "Line 1/2" if that's what RS-BA1 is configured for
- Check RS-BA1 settings for which audio device it uses for Speaker/Mic

---

## Quick Reference Checklist

Before freedvtnc2 will work on Windows, verify:

- [ ] codec2 built in MSYS2 (`libcodec2.dll` exists)
- [ ] `codec2.lib` created (MSVC import library)
- [ ] freedvtnc2 source patched with codec2 paths in `freedv_build.py`
- [ ] freedvtnc2 installed from patched source
- [ ] Runtime DLLs copied to Python directory:
  - [ ] `libcodec2.dll`
  - [ ] `libgcc_s_seh-1.dll`
  - [ ] `libwinpthread-1.dll`
- [ ] `tnc.py` patched (conditional Unix imports)
- [ ] `shell.py` patched (pyreadline3 fallback)
- [ ] `pyreadline3` installed
- [ ] Python Scripts directory in PATH

Test with:
```powershell
py -3.11 -c "from _freedv_cffi import ffi, lib; print('codec2 version:', lib.freedv_get_version())"
```

---

## Automated Setup

Instead of following all steps manually, you can use the automated scripts:

```powershell
cd hf-nomad

# Step 1: Check prerequisites (guides you through any missing items)
py -3.11 scripts/windows_prereqs.py

# Step 2: Run automated setup (builds freedvtnc2, installs hamlib, patches modules)
py -3.11 scripts/windows_setup.py
```

**windows_prereqs.py** checks for:
- Python 3.11+ (from python.org)
- Visual Studio Build Tools with MSVC
- MSYS2 installation
- codec2 built in MSYS2
- MinGW runtime DLLs

**windows_setup.py** automates:
- Creating MSVC import library from codec2 DLL
- Downloading and patching freedvtnc2 source
- Installing freedvtnc2 with codec2 paths
- Copying runtime DLLs to Python directory
- Patching tnc.py and shell.py for Windows compatibility
- Installing Hamlib
