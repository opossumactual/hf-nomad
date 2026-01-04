#!/bin/bash
#
# hf-nomad configuration wizard v0.1.0
# Interactive setup for radio, audio, and PTT configuration
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
header() { echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}\n"; }

# Config directory
CONFIG_DIR="$HOME/.config/hf-nomad"
CONFIG_FILE="$CONFIG_DIR/config"

# Selected values
RADIO_SERIAL=""
RADIO_MODEL=""
RADIO_MODEL_NAME=""
AUDIO_INPUT=""
AUDIO_OUTPUT=""
PTT_METHOD=""
FREEDV_MODE="DATAC1"
RIGCTLD_PORT="4532"
KISS_PORT="8001"

# -----------------------------------------------------------------------------
# Serial Port Detection
# -----------------------------------------------------------------------------
detect_serial_ports() {
    header "Serial Port Detection"

    local ports=()
    local descriptions=()
    local idx=1

    # Scan /dev/serial/by-id/
    if [ -d /dev/serial/by-id ]; then
        for port in /dev/serial/by-id/*; do
            if [ -e "$port" ]; then
                ports+=("$port")

                # Try to identify known radios
                local desc=""
                case "$port" in
                    *Icom*IC-705*|*IC-705*)
                        desc="Icom IC-705 (detected)"
                        ;;
                    *Icom*IC-7300*|*IC-7300*)
                        desc="Icom IC-7300 (detected)"
                        ;;
                    *Xiegu*G90*|*G90*)
                        desc="Xiegu G90 (detected)"
                        ;;
                    *Silicon_Labs*|*CP210*)
                        desc="USB-Serial (CP210x) - Digirig/Generic"
                        ;;
                    *FTDI*|*FT232*)
                        desc="USB-Serial (FTDI) - Generic"
                        ;;
                    *CH340*|*CH341*)
                        desc="USB-Serial (CH340) - Generic"
                        ;;
                    *)
                        desc="USB-Serial"
                        ;;
                esac
                descriptions+=("$desc")
            fi
        done
    fi

    if [ ${#ports[@]} -eq 0 ]; then
        warn "No serial ports found in /dev/serial/by-id/"
        echo "This is normal if:"
        echo "  - Your radio is not connected"
        echo "  - You're using VOX-only (no CAT control)"
        echo "  - Your interface uses a different connection method"
        echo ""
    else
        echo "Found serial ports:"
        echo ""
        for i in "${!ports[@]}"; do
            local shortname=$(basename "${ports[$i]}")
            echo -e "  ${BOLD}[$((i+1))]${NC} ${descriptions[$i]}"
            echo "      $shortname"
            echo ""
        done
    fi

    echo -e "  ${BOLD}[M]${NC} Manual entry (type path)"
    echo -e "  ${BOLD}[N]${NC} None (VOX only, no CAT control)"
    echo ""

    while true; do
        read -rp "Select serial port [1-${#ports[@]}/M/N]: " choice

        case "$choice" in
            [1-9]|[1-9][0-9])
                if [ "$choice" -le "${#ports[@]}" ] 2>/dev/null; then
                    RADIO_SERIAL="${ports[$((choice-1))]}"
                    success "Selected: $(basename "$RADIO_SERIAL")"
                    break
                else
                    warn "Invalid selection"
                fi
                ;;
            [Mm])
                echo ""
                echo "Examples:"
                echo "  /dev/ttyUSB0"
                echo "  /dev/ttyACM0"
                echo "  /dev/serial/by-id/usb-Silicon_Labs_CP210x..."
                echo ""
                read -rp "Enter serial port path: " RADIO_SERIAL
                if [ -e "$RADIO_SERIAL" ]; then
                    success "Selected: $RADIO_SERIAL"
                    break
                else
                    warn "Port does not exist: $RADIO_SERIAL"
                fi
                ;;
            [Nn])
                RADIO_SERIAL="none"
                success "No serial port (VOX mode)"
                break
                ;;
            *)
                warn "Invalid choice"
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Radio Model Selection
# -----------------------------------------------------------------------------
select_radio_model() {
    header "Radio Model Selection"

    if [ "$RADIO_SERIAL" = "none" ]; then
        RADIO_MODEL="none"
        RADIO_MODEL_NAME="None (VOX)"
        info "Skipping radio model selection (VOX mode)"
        return
    fi

    # Check if rigctl is available
    if ! command -v rigctl &> /dev/null; then
        error "rigctl not found. Please run install.sh first."
    fi

    # Common ham radio models
    echo "Common radio models:"
    echo ""
    echo -e "  ${BOLD}[1]${NC} Icom IC-705        (model 3085)"
    echo -e "  ${BOLD}[2]${NC} Icom IC-7300       (model 3073)"
    echo -e "  ${BOLD}[3]${NC} Yaesu FT-891       (model 1036)"
    echo -e "  ${BOLD}[4]${NC} Yaesu FT-991/991A  (model 1035)"
    echo -e "  ${BOLD}[5]${NC} Yaesu FT-817/818   (model 1020/1041)"
    echo -e "  ${BOLD}[6]${NC} Xiegu G90          (model 3088)"
    echo -e "  ${BOLD}[7]${NC} Xiegu X6100        (model 3087)"
    echo ""
    echo -e "  ${BOLD}[S]${NC} Search hamlib models"
    echo -e "  ${BOLD}[M]${NC} Manual entry (enter model number)"
    echo ""

    while true; do
        read -rp "Select radio model [1-7/S/M]: " choice

        case "$choice" in
            1)
                RADIO_MODEL="3085"
                RADIO_MODEL_NAME="Icom IC-705"
                break
                ;;
            2)
                RADIO_MODEL="3073"
                RADIO_MODEL_NAME="Icom IC-7300"
                break
                ;;
            3)
                RADIO_MODEL="1036"
                RADIO_MODEL_NAME="Yaesu FT-891"
                break
                ;;
            4)
                RADIO_MODEL="1035"
                RADIO_MODEL_NAME="Yaesu FT-991"
                break
                ;;
            5)
                echo "  [a] FT-817 (model 1020)"
                echo "  [b] FT-818 (model 1041)"
                read -rp "Select [a/b]: " subchoice
                case "$subchoice" in
                    [Aa])
                        RADIO_MODEL="1020"
                        RADIO_MODEL_NAME="Yaesu FT-817"
                        ;;
                    [Bb])
                        RADIO_MODEL="1041"
                        RADIO_MODEL_NAME="Yaesu FT-818"
                        ;;
                    *)
                        warn "Invalid choice"
                        continue
                        ;;
                esac
                break
                ;;
            6)
                RADIO_MODEL="3088"
                RADIO_MODEL_NAME="Xiegu G90"
                break
                ;;
            7)
                RADIO_MODEL="3087"
                RADIO_MODEL_NAME="Xiegu X6100"
                break
                ;;
            [Ss])
                read -rp "Search for radio (e.g., 'kenwood', '7300'): " search
                echo ""
                echo -e "${BOLD}Model#  Manufacturer         Radio${NC}"
                echo "------  ------------         -----"
                rigctl -l | grep -i "$search" | head -20 | while read -r num mfg model rest; do
                    printf "%-7s %-20s %s\n" "$num" "$mfg" "$model"
                done
                echo ""
                read -rp "Enter model number from first column: " RADIO_MODEL
                if [ -n "$RADIO_MODEL" ]; then
                    # Try to get the model name from rigctl
                    local model_info
                    model_info=$(rigctl -l | awk -v m="$RADIO_MODEL" '$1 == m {print $2, $3}')
                    if [ -n "$model_info" ]; then
                        RADIO_MODEL_NAME="$model_info"
                    else
                        RADIO_MODEL_NAME="Hamlib model $RADIO_MODEL"
                    fi
                    break
                else
                    warn "No model entered"
                fi
                ;;
            [Mm])
                echo ""
                echo "Tip: Find model numbers at: rigctl -l | less"
                echo "Examples: IC-705=3085, IC-7300=3073, FT-891=1036"
                echo ""
                read -rp "Enter hamlib model number: " RADIO_MODEL
                # Try to get the model name from rigctl
                local model_info
                model_info=$(rigctl -l | awk -v m="$RADIO_MODEL" '$1 == m {print $2, $3}')
                if [ -n "$model_info" ]; then
                    RADIO_MODEL_NAME="$model_info"
                else
                    RADIO_MODEL_NAME="Hamlib model $RADIO_MODEL"
                fi
                break
                ;;
            *)
                warn "Invalid choice"
                ;;
        esac
    done

    success "Selected: $RADIO_MODEL_NAME (model $RADIO_MODEL)"
}

# -----------------------------------------------------------------------------
# Audio Device Detection
# -----------------------------------------------------------------------------
detect_audio_devices() {
    header "Audio Device Selection"

    echo "Detecting audio devices..."
    echo ""

    # Get list of audio devices
    local input_devices=()
    local output_devices=()

    # Use arecord/aplay to list devices
    if command -v arecord &> /dev/null; then
        echo -e "${BOLD}Input devices (capture):${NC}"
        echo ""

        local idx=0
        while IFS= read -r line; do
            if [[ "$line" =~ ^card ]]; then
                echo -e "  ${BOLD}[$idx]${NC} $line"
                input_devices+=("$idx")
                ((idx++))
            fi
        done < <(arecord -l 2>/dev/null || true)

        if [ ${#input_devices[@]} -eq 0 ]; then
            warn "No input devices found"
        fi
        echo ""
    fi

    if command -v aplay &> /dev/null; then
        echo -e "${BOLD}Output devices (playback):${NC}"
        echo ""

        local idx=0
        while IFS= read -r line; do
            if [[ "$line" =~ ^card ]]; then
                echo -e "  ${BOLD}[$idx]${NC} $line"
                output_devices+=("$idx")
                ((idx++))
            fi
        done < <(aplay -l 2>/dev/null || true)

        if [ ${#output_devices[@]} -eq 0 ]; then
            warn "No output devices found"
        fi
        echo ""
    fi

    # Input device selection
    echo "Select the audio INPUT device (from radio/interface to computer):"
    echo "  Tip: Look for 'USB Audio', 'Digirig', 'C-Media', or your interface name"
    echo ""

    while true; do
        read -rp "Enter input device number: " AUDIO_INPUT
        if [[ "$AUDIO_INPUT" =~ ^[0-9]+$ ]]; then
            success "Input device: $AUDIO_INPUT"
            break
        else
            warn "Please enter a number"
        fi
    done

    # Output device selection
    echo ""
    echo "Select the audio OUTPUT device (from computer to radio/interface):"
    echo "  Tip: Usually the same card number as input for USB interfaces"
    echo ""

    while true; do
        read -rp "Enter output device number (or 'same' for same as input): " choice
        if [ "$choice" = "same" ]; then
            AUDIO_OUTPUT="$AUDIO_INPUT"
            success "Output device: $AUDIO_OUTPUT (same as input)"
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]]; then
            AUDIO_OUTPUT="$choice"
            success "Output device: $AUDIO_OUTPUT"
            break
        else
            warn "Please enter a number or 'same'"
        fi
    done
}

# -----------------------------------------------------------------------------
# PTT Method Selection
# -----------------------------------------------------------------------------
select_ptt_method() {
    header "PTT Method Selection"

    if [ "$RADIO_SERIAL" = "none" ]; then
        PTT_METHOD="none"
        info "Using VOX (no PTT control)"
        return
    fi

    echo "How should PTT (Push-to-Talk) be controlled?"
    echo ""
    echo -e "  ${BOLD}[1]${NC} CAT command via rigctld ${GREEN}(Recommended)${NC}"
    echo "      Works with most modern radios"
    echo ""
    echo -e "  ${BOLD}[2]${NC} RTS (Request To Send) pin"
    echo "      Hardware PTT via serial port RTS line"
    echo ""
    echo -e "  ${BOLD}[3]${NC} DTR (Data Terminal Ready) pin"
    echo "      Hardware PTT via serial port DTR line"
    echo ""
    echo -e "  ${BOLD}[4]${NC} VOX (Voice Operated Switch)"
    echo "      Radio triggers on audio, no PTT signal"
    echo ""

    while true; do
        read -rp "Select PTT method [1-4]: " choice

        case "$choice" in
            1)
                PTT_METHOD="rigctld"
                success "PTT method: CAT via rigctld"
                break
                ;;
            2)
                PTT_METHOD="RTS"
                success "PTT method: RTS"
                break
                ;;
            3)
                PTT_METHOD="DTR"
                success "PTT method: DTR"
                break
                ;;
            4)
                PTT_METHOD="none"
                success "PTT method: VOX (none)"
                break
                ;;
            *)
                warn "Invalid choice"
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# FreeDV Mode Selection
# -----------------------------------------------------------------------------
select_freedv_mode() {
    header "FreeDV Mode Selection"

    echo "Select the FreeDV data mode:"
    echo ""
    echo -e "  ${BOLD}[1]${NC} DATAC1 ${GREEN}(Recommended for HF)${NC}"
    echo "      980 bps, robust, works down to 5dB SNR"
    echo ""
    echo -e "  ${BOLD}[2]${NC} DATAC3"
    echo "      Faster, but needs better conditions"
    echo ""
    echo -e "  ${BOLD}[3]${NC} DATAC4"
    echo "      Best for poor conditions, works down to -8dB SNR"
    echo ""

    while true; do
        read -rp "Select FreeDV mode [1-3]: " choice

        case "$choice" in
            1)
                FREEDV_MODE="DATAC1"
                success "FreeDV mode: DATAC1"
                break
                ;;
            2)
                FREEDV_MODE="DATAC3"
                success "FreeDV mode: DATAC3"
                break
                ;;
            3)
                FREEDV_MODE="DATAC4"
                success "FreeDV mode: DATAC4"
                break
                ;;
            *)
                warn "Invalid choice"
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Install Services and Scripts
# -----------------------------------------------------------------------------
install_services() {
    header "Installing Services"

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local user_systemd="$HOME/.config/systemd/user"
    local user_bin="$HOME/.local/bin"

    # Install systemd user services
    info "Installing systemd user services..."
    mkdir -p "$user_systemd"
    cp "$script_dir/systemd/hf-nomad-rigctld.service" "$user_systemd/"
    cp "$script_dir/systemd/hf-nomad-modem.service" "$user_systemd/"
    cp "$script_dir/systemd/hf-nomad.target" "$user_systemd/"
    success "Installed services to $user_systemd/"

    # Install hf-nomad script
    info "Installing hf-nomad control script..."
    mkdir -p "$user_bin"
    cp "$script_dir/scripts/hf-nomad" "$user_bin/"
    chmod +x "$user_bin/hf-nomad"
    success "Installed hf-nomad to $user_bin/"

    # Check if ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$user_bin:"* ]]; then
        warn "$user_bin is not in PATH"
        echo "Add this to your ~/.bashrc or ~/.zshrc:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi

    # Reload systemd
    if command -v systemctl &> /dev/null; then
        systemctl --user daemon-reload 2>/dev/null || true
        success "Reloaded systemd user daemon"
    fi
}

# -----------------------------------------------------------------------------
# Generate Config Files
# -----------------------------------------------------------------------------
generate_configs() {
    header "Generating Configuration"

    mkdir -p "$CONFIG_DIR"

    # Master config file (shell sourceable)
    info "Writing master config..."
    cat > "$CONFIG_FILE" << EOF
# hf-nomad configuration
# Generated: $(date)

# Radio settings
RADIO_SERIAL="$RADIO_SERIAL"
RADIO_MODEL="$RADIO_MODEL"
RADIO_MODEL_NAME="$RADIO_MODEL_NAME"

# Audio settings
AUDIO_INPUT_DEVICE="$AUDIO_INPUT"
AUDIO_OUTPUT_DEVICE="$AUDIO_OUTPUT"

# FreeDV settings
FREEDV_MODE="$FREEDV_MODE"

# PTT settings
PTT_METHOD="$PTT_METHOD"

# Network ports
RIGCTLD_PORT="$RIGCTLD_PORT"
KISS_PORT="$KISS_PORT"
EOF
    success "Created: $CONFIG_FILE"

    # freedvtnc2 config
    info "Writing freedvtnc2 config..."
    mkdir -p "$HOME/.config/freedvtnc2"
    cat > "$HOME/.config/freedvtnc2/config" << EOF
# freedvtnc2 configuration
# Generated by hf-nomad

input-device = $AUDIO_INPUT
output-device = $AUDIO_OUTPUT
mode = $FREEDV_MODE
kiss-tcp-port = $KISS_PORT
EOF

    # Add PTT config based on method
    if [ "$PTT_METHOD" = "rigctld" ]; then
        cat >> "$HOME/.config/freedvtnc2/config" << EOF
ptt-method = rigctld
rigctld-port = $RIGCTLD_PORT
EOF
    elif [ "$PTT_METHOD" = "RTS" ] || [ "$PTT_METHOD" = "DTR" ]; then
        cat >> "$HOME/.config/freedvtnc2/config" << EOF
ptt-method = $PTT_METHOD
ptt-device = $RADIO_SERIAL
EOF
    fi
    success "Created: ~/.config/freedvtnc2/config"

    # Reticulum config with KISS interface
    info "Writing Reticulum config..."
    mkdir -p "$HOME/.reticulum"

    # Check if config exists, backup if so
    if [ -f "$HOME/.reticulum/config" ]; then
        cp "$HOME/.reticulum/config" "$HOME/.reticulum/config.backup.$(date +%Y%m%d%H%M%S)"
        warn "Backed up existing Reticulum config"
    fi

    cat > "$HOME/.reticulum/config" << EOF
# Reticulum configuration
# Generated by hf-nomad

[reticulum]
  enable_transport = no
  share_instance = yes

[logging]
  loglevel = 4

[interfaces]
  [[Default Interface]]
    type = AutoInterface
    enabled = yes

  [[HF Radio via FreeDV]]
    type = TCPClientInterface
    enabled = yes
    kiss_framing = True
    target_host = 127.0.0.1
    target_port = $KISS_PORT
EOF
    success "Created: ~/.reticulum/config"

    # NomadNet config
    info "Writing NomadNet config..."
    mkdir -p "$HOME/.nomadnetwork"

    if [ -f "$HOME/.nomadnetwork/config" ]; then
        cp "$HOME/.nomadnetwork/config" "$HOME/.nomadnetwork/config.backup.$(date +%Y%m%d%H%M%S)"
        warn "Backed up existing NomadNet config"
    fi

    cat > "$HOME/.nomadnetwork/config" << EOF
# NomadNet configuration
# Generated by hf-nomad
# Optimized for HF radio operation

[node]
  enable_node = no

[client]
  try_propagation_on_send_fail = no
  user_interface = text

[textui]
  intro_time = 1
  mouse_enabled = True

[announce]
  announce_interval = 720
EOF
    success "Created: ~/.nomadnetwork/config"
}

# -----------------------------------------------------------------------------
# Print Summary
# -----------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN} Configuration Complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo "Configuration summary:"
    echo "  Radio:      $RADIO_MODEL_NAME"
    echo "  Serial:     $RADIO_SERIAL"
    echo "  Audio In:   Device $AUDIO_INPUT"
    echo "  Audio Out:  Device $AUDIO_OUTPUT"
    echo "  PTT:        $PTT_METHOD"
    echo "  FreeDV:     $FREEDV_MODE"
    echo ""
    echo "Config files created:"
    echo "  $CONFIG_FILE"
    echo "  ~/.config/freedvtnc2/config"
    echo "  ~/.reticulum/config"
    echo "  ~/.nomadnetwork/config"
    echo ""
    echo "Installed:"
    echo "  ~/.config/systemd/user/hf-nomad-*.service"
    echo "  ~/.local/bin/hf-nomad"
    echo ""
    echo -e "${BOLD}Quick Start:${NC}"
    echo ""
    echo "  hf-nomad start       # Start the HF radio stack"
    echo "  hf-nomad status      # Check status"
    echo "  nomadnet             # Launch NomadNet"
    echo ""
    echo -e "${BOLD}Other Commands:${NC}"
    echo ""
    echo "  hf-nomad test-radio  # Test CAT connection"
    echo "  hf-nomad test-audio  # Test audio devices"
    echo "  hf-nomad monitor     # Watch live output"
    echo "  hf-nomad enable      # Enable autostart on login"
    echo "  hf-nomad help        # Show all commands"
    echo ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    echo ""
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE} hf-nomad Configuration Wizard${NC}"
    echo -e "${BLUE}======================================${NC}"

    detect_serial_ports
    select_radio_model
    detect_audio_devices
    select_ptt_method
    select_freedv_mode
    generate_configs
    install_services
    print_summary
}

main "$@"
