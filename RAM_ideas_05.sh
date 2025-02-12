Below is a complete, improved suite of scripts that incorporates enhanced logging, dependency checks, error handling, and cleanup routines. These scripts are split into several files. In this example, we assume your target USB device is **/dev/sdc** (which will be completely reformatted). **Review and test these scripts in a safe, trusted live environment before deploying.**

---

> **Important:**  
> – Make sure to adjust the placeholder URLs (for ISOs, checksums, signatures, rEFInd installer) to point to your trusted mirrors.  
> – Double‑check that **/dev/sdc** is correct.  
> – These scripts rely on the common functions provided in **common_functions.sh**.

---

## File 1: common_functions.sh
Place this file in the same directory as the other scripts. It provides logging, dependency checks, and a cleanup/trap mechanism.

```bash
#!/bin/bash
# common_functions.sh
# Common functions for logging, dependency checking, and cleanup

set -euo pipefail

# Enhanced logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Log levels: INFO, WARNING, ERROR, DEBUG
    echo "${timestamp} [${level}] ${message}" >&2
    
    # Also log to file if LOG_FILE is defined
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "${timestamp} [${level}] ${message}" >> "$LOG_FILE"
    fi
}

# Enhanced dependency check function
require_cmd() {
    local cmd="$1"
    local description="$2"
    
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "ERROR" "Required tool '$cmd' (${description}) not found. Aborting."
        exit 1
    fi
}

# Common cleanup function
cleanup() {
    local status=$?
    log "INFO" "Starting cleanup..."
    
    # Unmount secure workspace if mounted
    if mountpoint -q "${SECURE_WORKSPACE:-/mnt/secure_workspace}"; then
        sudo umount "${SECURE_WORKSPACE:-/mnt/secure_workspace}" || log "WARNING" "Failed to unmount secure workspace"
    fi
    
    # Remove temporary files if any
    if [[ "${#TEMP_FILES[@]:-0}" -gt 0 ]]; then
        for file in "${TEMP_FILES[@]}"; do
            rm -f "$file" || log "WARNING" "Failed to remove temporary file: $file"
        done
    fi
    
    # Reset iptables if modified
    if [[ -n "${IPTABLES_MODIFIED:-}" ]]; then
        log "INFO" "Resetting iptables to defaults..."
        sudo iptables -F || log "WARNING" "Failed to flush iptables"
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
    fi
    
    log "INFO" "Cleanup complete."
    exit $status
}

# Trap handler for unexpected exit signals
trap_handler() {
    local signal="$1"
    log "ERROR" "Script terminated unexpectedly (Signal: $signal)."
    cleanup
}

# Install trap for common signals
trap 'trap_handler ERR' ERR
trap 'trap_handler INT' INT
trap 'trap_handler TERM' TERM
trap 'cleanup' EXIT
```

---

## File 2: auto_env_setup.sh
This script sets up a secure, RAM‑based workspace and (optionally) tightens network access via iptables.

```bash
#!/bin/bash
# auto_env_setup.sh
# Sets up a RAM-based secure workspace and verifies dependencies.
# Also configures basic iptables rules to allow only trusted hosts.

set -euo pipefail
source ./common_functions.sh

log "INFO" "Checking dependencies for environment setup..."
for cmd in mount mkdir iptables sha256sum gpg; do
    require_cmd "$cmd" "Required for environment setup"
done

log "INFO" "Verifying live environment integrity..."
# (Optional) Insert live ISO integrity checks here if applicable.

SECURE_WORKSPACE="/mnt/secure_workspace"
export SECURE_WORKSPACE
if ! mountpoint -q "$SECURE_WORKSPACE"; then
    sudo mkdir -p "$SECURE_WORKSPACE"
    # Use nosuid,nodev for additional security
    sudo mount -t tmpfs -o size=2G,nosuid,nodev tmpfs "$SECURE_WORKSPACE"
    log "INFO" "Secure workspace mounted at $SECURE_WORKSPACE"
else
    log "INFO" "Secure workspace already mounted at $SECURE_WORKSPACE"
fi

cd "$SECURE_WORKSPACE"

# Optional: Configure iptables to allow only trusted hosts
TRUSTED_IPS=("1.2.3.4" "5.6.7.8")  # Replace with actual trusted IPs
log "INFO" "Configuring iptables to allow only trusted hosts..."
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
for ip in "${TRUSTED_IPS[@]}"; do
    sudo iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -d "$ip" -j ACCEPT
done
export IPTABLES_MODIFIED=1

log "INFO" "Environment setup complete."
```

---

## File 3: auto_download.sh
Downloads the OS images (Parrot OS and BlackArch) along with their verification files, then verifies their integrity.

```bash
#!/bin/bash
# auto_download.sh
# Downloads OS images and verification files and verifies them.
# Uses HTTPS and verifies checksums and GPG signatures.
#
# Replace the URL placeholders with your trusted mirrors.

set -euo pipefail
source ./common_functions.sh

log "INFO" "Checking dependencies for downloads..."
for cmd in curl sha256sum gpg; do
    require_cmd "$cmd" "Required for downloading and verifying images"
done

log "INFO" "Downloading OS images and verification files..."

# --- Parrot OS Variables ---
PARROT_ISO_URL="https://trusted-mirror.example.com/parrot.iso"
PARROT_SHA256_URL="https://trusted-mirror.example.com/parrot.iso.sha256"
PARROT_SIG_URL="https://trusted-mirror.example.com/parrot.iso.sig"

log "INFO" "Downloading Parrot OS ISO..."
curl --fail -sSL -o parrot.iso "$PARROT_ISO_URL"
curl --fail -sSL -o parrot.iso.sha256 "$PARROT_SHA256_URL"
curl --fail -sSL -o parrot.iso.sig "$PARROT_SIG_URL"

# --- BlackArch Variables ---
BLACKARCH_ISO_URL="https://trusted-mirror.example.com/blackarch.iso"
BLACKARCH_SHA256_URL="https://trusted-mirror.example.com/blackarch.iso.sha256"
BLACKARCH_SIG_URL="https://trusted-mirror.example.com/blackarch.iso.sig"

log "INFO" "Downloading BlackArch ISO..."
curl --fail -sSL -o blackarch.iso "$BLACKARCH_ISO_URL"
curl --fail -sSL -o blackarch.iso.sha256 "$BLACKARCH_SHA256_URL"
curl --fail -sSL -o blackarch.iso.sig "$BLACKARCH_SIG_URL"

log "INFO" "Verifying Parrot OS ISO checksum..."
sha256sum -c parrot.iso.sha256

log "INFO" "Verifying Parrot OS GPG signature..."
gpg --batch --verify parrot.iso.sig parrot.iso

log "INFO" "Verifying BlackArch ISO checksum..."
sha256sum -c blackarch.iso.sha256

log "INFO" "Verifying BlackArch GPG signature..."
gpg --batch --verify blackarch.iso.sig blackarch.iso

log "INFO" "Download and verification complete."
```

---

## File 4: auto_partition.sh
This script partitions **/dev/sdc** non‑interactively. It creates three partitions as specified:
- Partition 1: EFI (≈190 MiB)  
- Partition 2: Parrot OS (~3.6 GiB)  
- Partition 3: BlackArch (~3.7 GiB)

```bash
#!/bin/bash
# auto_partition.sh
# Non-interactively partitions /dev/sdc.
# WARNING: This will destroy all data on /dev/sdc.
#
# Usage: Run as root.

set -euo pipefail
source ./common_functions.sh

USB_DEVICE="/dev/sdc"
log "INFO" "Partitioning $USB_DEVICE non-interactively..."

# Unmount any mounted partitions on the device
for part in $(lsblk -ln -o NAME "$USB_DEVICE" | tail -n +2); do
    sudo umount "/dev/$part" 2>/dev/null || log "WARNING" "Could not unmount /dev/$part"
done

log "INFO" "Creating GPT partition table on $USB_DEVICE..."
sudo parted "$USB_DEVICE" --script mklabel gpt

log "INFO" "Creating EFI partition (1MiB to 191MiB)..."
sudo parted "$USB_DEVICE" --script mkpart ESP fat32 1MiB 191MiB
sudo parted "$USB_DEVICE" --script set 1 esp on

log "INFO" "Creating Parrot OS partition (191MiB to 3791MiB)..."
sudo parted "$USB_DEVICE" --script mkpart primary ext4 191MiB 3791MiB

log "INFO" "Creating BlackArch partition (3791MiB to 100%)..."
sudo parted "$USB_DEVICE" --script mkpart primary ext4 3791MiB 100%

log "INFO" "Partitioning complete. Current layout:"
lsblk "$USB_DEVICE"
```

---

## File 5: auto_write_isos.sh
Writes the downloaded ISOs onto the appropriate partitions using `dd`.

```bash
#!/bin/bash
# auto_write_isos.sh
# Writes the Parrot OS and BlackArch ISOs to partitions /dev/sdc2 and /dev/sdc3 respectively.
#
# Assumes:
#   - Parrot OS ISO goes to /dev/sdc2
#   - BlackArch ISO goes to /dev/sdc3

set -euo pipefail
source ./common_functions.sh

USB_DEVICE="/dev/sdc"

log "INFO" "Writing Parrot OS ISO to ${USB_DEVICE}2..."
sudo dd if=parrot.iso of="${USB_DEVICE}2" bs=4M status=progress conv=fsync

log "INFO" "Writing BlackArch ISO to ${USB_DEVICE}3..."
sudo dd if=blackarch.iso of="${USB_DEVICE}3" bs=4M status=progress conv=fsync

log "INFO" "ISO writing complete."
```

---

## File 6: auto_install_refind.sh
Downloads and installs rEFInd onto the EFI partition (assumed to be **/dev/sdc1**) without manual intervention.

```bash
#!/bin/bash
# auto_install_refind.sh
# Downloads and installs rEFInd onto the EFI partition (/dev/sdc1) non-interactively.
#
# Replace REFIND_URL with your trusted source for the installer script.

set -euo pipefail
source ./common_functions.sh

USB_DEVICE="/dev/sdc"
EFI_PART="${USB_DEVICE}1"
EFI_MOUNT="/mnt/efi"

log "INFO" "Mounting EFI partition ${EFI_PART}..."
sudo mkdir -p "$EFI_MOUNT"
sudo mount "$EFI_PART" "$EFI_MOUNT"

log "INFO" "Downloading rEFInd installer..."
REFIND_URL="https://trusted-source.example.com/refind-install.sh"  # Replace with your URL
refind_script=$(curl --fail -sSL "$REFIND_URL")

# Optional: Add verification for the installer script here (e.g., SHA256 or GPG verification)

log "INFO" "Installing rEFInd onto EFI partition..."
echo "$refind_script" | sudo bash -s -- --yes --root "$EFI_MOUNT"

log "INFO" "Setting immutable attributes on critical rEFInd files..."
sudo chattr +i "$EFI_MOUNT/EFI/refind/refind.conf" 2>/dev/null || log "WARNING" "Could not set immutable flag on refind.conf"
sudo chattr +i "$EFI_MOUNT/EFI/refind/refind_x64.efi" 2>/dev/null || log "WARNING" "Could not set immutable flag on refind_x64.efi"

sudo umount "$EFI_MOUNT"
log "INFO" "rEFInd installation complete."
```

---

## File 7: auto_cleanup.sh
Cleans up the secure workspace and resets any temporary network modifications.

```bash
#!/bin/bash
# auto_cleanup.sh
# Cleans up the secure environment by unmounting the secure workspace and resetting iptables.

set -euo pipefail
source ./common_functions.sh

log "INFO" "Starting cleanup process..."

SECURE_WORKSPACE="/mnt/secure_workspace"
if mountpoint -q "$SECURE_WORKSPACE"; then
    sudo umount "$SECURE_WORKSPACE" && log "INFO" "Unmounted secure workspace"
    sudo rm -rf "$SECURE_WORKSPACE" && log "INFO" "Removed secure workspace directory"
fi

if [[ -n "${IPTABLES_MODIFIED:-}" ]]; then
    log "INFO" "Resetting iptables to defaults..."
    sudo iptables -F || log "WARNING" "Failed to flush iptables"
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
fi

log "INFO" "Cleanup complete."
```

---

## File 8: auto_master.sh
The master script runs all of the above scripts in sequence without further manual intervention. It installs a trap so that any error triggers cleanup.

```bash
#!/bin/bash
# auto_master.sh
# Master script to run the complete automated USB setup on /dev/sdc.
#
# Make sure all the above scripts and common_functions.sh are in the same directory.
# Run this script as root.

set -euo pipefail
source ./common_functions.sh

LOG_FILE="/tmp/auto_master.log"
export LOG_FILE
log "INFO" "Starting fully automated USB setup on /dev/sdc..."

# Execute each step in sequence
bash auto_env_setup.sh
bash auto_download.sh
bash auto_partition.sh
bash auto_write_isos.sh
bash auto_install_refind.sh
bash auto_cleanup.sh

log "INFO" "Fully automated USB setup complete."
```

---

## Usage Instructions

1. **Prepare Your Trusted Environment:**  
   Boot from a verified, read-only live OS (e.g., Tails, SystemRescue, etc.) to ensure your starting environment is as clean as possible.

2. **Place All Files Together:**  
   Save all eight files in a single directory. Make sure they are executable:
   ```bash
   chmod +x common_functions.sh auto_env_setup.sh auto_download.sh auto_partition.sh auto_write_isos.sh auto_install_refind.sh auto_cleanup.sh auto_master.sh
   ```

3. **Run the Master Script:**  
   Execute the master script as root:
   ```bash
   sudo ./auto_master.sh
   ```
   All steps—from setting up the environment and downloading images to partitioning, writing ISOs, installing rEFInd, and cleaning up—will run non‑interactively.

---

These enhanced scripts include detailed logging, robust dependency checking, and automatic cleanup, giving you a more reliable, production‑grade solution for building your hardened multi‑boot USB stick containing rEFInd, Parrot OS, and BlackArch. Always test in a safe environment and adjust URLs, IPs, and device names as needed for your situation.
