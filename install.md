# Windows Installation Guide

This guide walks you through installing hf-nomad on Windows 10/11.

## Prerequisites

- Windows 10 or 11
- An HF radio with USB CAT control and audio interface (e.g., IC-705, IC-7300, FT-891)
- Basic familiarity with command line
- About 2GB disk space for build tools

## Step 1: Install Python 3.11

**Important:** Use Python 3.11 specifically. Newer versions (3.12, 3.13, 3.14) may not have prebuilt wheels for all dependencies.

1. Download Python 3.11 from https://www.python.org/downloads/release/python-3119/
   - Get "Windows installer (64-bit)"
2. Run the installer
3. **Important**: Check "Add Python to PATH" at the bottom of the installer
4. Click "Install Now"

Verify installation:
```cmd
py -3.11 --version
```

Should show Python 3.11.x.

## Step 2: Install MSYS2

MSYS2 provides the build tools needed to compile codec2.

1. Download MSYS2 from https://www.msys2.org/
2. Run the installer, use default options
3. After install, MSYS2 will open a terminal
4. Run: `pacman -Syu` (update packages, may need to close and reopen)

## Step 3: Build codec2

freedvtnc2 requires a recent version of codec2 that isn't available as a Windows binary. We need to build it from source.

Open **"MSYS2 MinGW 64-bit"** from the Start menu (not "MSYS2 MSYS" or "MSYS2 UCRT"):

```bash
# Install build tools (the toolchain includes gcc, make, etc.)
pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake git

# When prompted, press Enter to install all toolchain components

# Clone codec2
cd ~
git clone https://github.com/drowe67/codec2.git
cd codec2

# Build
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
make -j4

# Note the path to libcodec2.dll
# Usually: ~/codec2/build/src/libcodec2.dll
```

Now copy the DLLs to your Python directory. Open **Windows Command Prompt** (not MSYS2):

```cmd
# Find your Python directory
py -3.11 -c "import sys; print(sys.prefix)"

# Copy codec2 DLL and MinGW runtime DLLs to Python directory
# Adjust paths as needed for your username
copy C:\msys64\home\YOUR_USER\codec2\build\src\libcodec2.dll C:\Users\YOUR_USER\AppData\Local\Programs\Python\Python311\
copy C:\msys64\mingw64\bin\libgcc_s_seh-1.dll C:\Users\YOUR_USER\AppData\Local\Programs\Python\Python311\
copy C:\msys64\mingw64\bin\libwinpthread-1.dll C:\Users\YOUR_USER\AppData\Local\Programs\Python\Python311\
```

## Step 4: Create MSVC Import Library

Python's pip uses MSVC to compile, which needs a `.lib` file (not MinGW's `.dll.a`).

```cmd
# Install pefile to extract DLL exports
py -3.11 -m pip install pefile

# Create a Python script to generate the .def file
# Save this as make_def.py:
```

```python
import pefile
import sys

dll_path = sys.argv[1]
pe = pefile.PE(dll_path)

print("LIBRARY codec2")
print("EXPORTS")
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        print(f"    {exp.name.decode()}")
```

```cmd
# Run it to create codec2.def
py -3.11 make_def.py C:\msys64\home\YOUR_USER\codec2\build\src\libcodec2.dll > codec2.def

# Use MSVC lib.exe to create the import library
# (Requires Visual Studio Build Tools - see below if you don't have it)
lib /def:codec2.def /out:codec2.lib /machine:x64

# Copy codec2.lib to the codec2 build directory
copy codec2.lib C:\msys64\home\YOUR_USER\codec2\build\src\
```

**Note:** If you don't have `lib.exe`, install "Visual Studio Build Tools" from:
https://visualstudio.microsoft.com/visual-cpp-build-tools/
Select "Desktop development with C++" workload.

## Step 5: Install Hamlib

Hamlib provides `rigctld` for radio CAT control.

1. Download Windows binaries from: https://github.com/Hamlib/Hamlib/releases
2. Extract to `C:\hamlib` (or another location)
3. Add `C:\hamlib\bin` to your system PATH:
   - Search "environment variables" in Windows
   - Edit PATH, add `C:\hamlib\bin`

Verify:
```
rigctl --version
```

## Step 6: Install freedvtnc2 (Modified Build)

freedvtnc2 has hardcoded Unix paths that need to be modified for Windows.

```cmd
# First install other dependencies
py -3.11 -m pip install pyserial sounddevice pyaudio

# Download freedvtnc2 source
py -3.11 -m pip download freedvtnc2 --no-binary :all:
tar -xf freedvtnc2-*.tar.gz
cd freedvtnc2-*
```

Edit `freedv_build.py` and find the `ffibuilder.set_source()` call. Add your codec2 paths to `include_dirs` and `library_dirs`:

```python
ffibuilder.set_source(
    "_freedv",
    '#include "freedv_api.h"',
    libraries=["codec2"],
    include_dirs=[
        "/usr/local/include/codec2",  # existing
        "C:/msys64/home/YOUR_USER/codec2/src",  # ADD THIS
    ],
    library_dirs=[
        "/usr/local/lib",  # existing
        "C:/msys64/home/YOUR_USER/codec2/build/src",  # ADD THIS
    ],
)
```

Then install from the modified source:

```cmd
py -3.11 -m pip install .
```

**Note:** Keep this modified source folder - you'll need it if you ever reinstall freedvtnc2.

## Step 7: Install NomadNet

```cmd
py -3.11 -m pip install nomadnet
```

## Step 8: Download hf-nomad

```cmd
git clone https://github.com/opossumactual/hf-nomad.git
cd hf-nomad
git checkout windows-support
```

Or download and extract the ZIP from GitHub.

## Step 9: Configure

Run the configuration wizard:

```cmd
py -3.11 configure.py
```

This will:
1. Detect your COM ports and help you select your radio
2. Find audio devices
3. Configure PTT method
4. Generate config files

## Step 10: Test

Test your radio connection:
```cmd
py -3.11 hf_nomad.py test-radio
```

Test audio devices:
```cmd
py -3.11 hf_nomad.py test-audio
```

## Usage

Start the HF stack:
```cmd
py -3.11 hf_nomad.py start
```

Check status:
```cmd
py -3.11 hf_nomad.py status
```

Launch NomadNet (in a new terminal):
```cmd
py -3.11 -m nomadnet
```

Stop the HF stack:
```cmd
py -3.11 hf_nomad.py stop
```

## Troubleshooting

### "rigctl not found"
Add hamlib bin directory to PATH, or specify full path in config.

### "freedvtnc2 failed to install"
codec2 library not found. Make sure libcodec2.dll is in your PATH or Python directory.

### "COM port access denied"
Close any other programs using the COM port (radio control software, etc.)

### Audio device not found
Run `python hf_nomad.py test-audio` to list devices. Make sure your USB audio interface is connected.

### Firewall prompts
freedvtnc2 uses TCP port 8001 for KISS. Allow it through Windows Firewall if prompted.

## Config File Locations

Windows stores config files in:
- `%APPDATA%\hf-nomad\config.json` - Main configuration
- `%APPDATA%\freedvtnc2\config` - FreeDV TNC settings
- `%APPDATA%\Reticulum\config` - Reticulum network settings

## Getting Help

- Open an issue on GitHub
- Check the NomadNet/Reticulum documentation: https://reticulum.network/
- FreeDV TNC documentation: https://github.com/xssfox/freedvtnc2
