# Windows Installation Guide

This guide walks you through installing hf-nomad on Windows 10/11.

## Prerequisites

- Windows 10 or 11
- An HF radio with USB CAT control and audio interface (e.g., IC-705, IC-7300, FT-891)
- Basic familiarity with command line

## Step 1: Install Python 3.11+

1. Download Python from https://www.python.org/downloads/
2. Run the installer
3. **Important**: Check "Add Python to PATH" at the bottom of the installer
4. Click "Install Now"

Verify installation:
```
python --version
```

Should show Python 3.11 or higher.

## Step 2: Install MSYS2

MSYS2 provides the build tools needed to compile codec2.

1. Download MSYS2 from https://www.msys2.org/
2. Run the installer, use default options
3. After install, MSYS2 will open a terminal
4. Run: `pacman -Syu` (update packages, may need to close and reopen)

## Step 3: Build codec2

freedvtnc2 requires a recent version of codec2 that isn't available as a Windows binary. We need to build it from source.

Open **MSYS2 MinGW 64-bit** (not the regular MSYS2 terminal):

```bash
# Install build tools
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-make git

# Clone codec2
cd ~
git clone https://github.com/drowe67/codec2.git
cd codec2

# Build
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
mingw32-make -j4

# Note the path to libcodec2.dll
# Usually: ~/codec2/build/src/libcodec2.dll
```

Copy the DLL to your Python environment:
```bash
# Find where Python is installed (in regular Windows cmd/powershell)
python -c "import sys; print(sys.prefix)"

# Copy libcodec2.dll to that location
# Example: copy libcodec2.dll to C:\Users\YourName\AppData\Local\Programs\Python\Python311\
```

Alternative: Add the codec2 build directory to your system PATH.

## Step 4: Install Hamlib

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

## Step 5: Install Python Packages

Open Command Prompt or PowerShell:

```
pip install pyserial sounddevice
pip install freedvtnc2 nomadnet
```

If freedvtnc2 fails to install, codec2 wasn't found. Check:
- Is libcodec2.dll in your PATH or Python directory?
- Try: `set PATH=%PATH%;C:\path\to\codec2\build\src` then retry pip install

## Step 6: Download hf-nomad

```
git clone https://github.com/YOUR_USERNAME/hf-nomad.git
cd hf-nomad
git checkout windows-support
```

Or download and extract the ZIP from GitHub.

## Step 7: Configure

Run the configuration wizard:

```
python configure.py
```

This will:
1. Detect your COM ports and help you select your radio
2. Find audio devices
3. Configure PTT method
4. Generate config files

## Step 8: Test

Test your radio connection:
```
python hf_nomad.py test-radio
```

Test audio devices:
```
python hf_nomad.py test-audio
```

## Usage

Start the HF stack:
```
python hf_nomad.py start
```

Check status:
```
python hf_nomad.py status
```

Launch NomadNet (in a new terminal):
```
nomadnet
```

Stop the HF stack:
```
python hf_nomad.py stop
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
