Below is a revised, enhanced set of scripts. They now include additional checks, better logging, dependency verifications, and cleanup routines. Review these scripts carefully, adjust URLs and device names as needed, and test in a safe environment before running on your target USB device. All scripts assume a trusted live environment and that **/dev/sdc** is your target device (all data on it will be destroyed).

> **Warning:**  
> These scripts will completely reformat **/dev/sdc**. Double‑check the device name and be sure you are running in a trusted environment.

---

> **Notes on Improvements:**  
> - **Dependency Checks:** Each script (where appropriate) now checks for required commands.  
> - **Error Handling & Logging:** We use `set -euo pipefail` plus additional log messages.  
> - **Non‑Interactive Mode:** No user intervention is needed (except that you must verify the target device is correct before running).  
> - **Network Isolation (Optional):** The environment setup script still has a placeholder for iptables rules.  
> - **Cleanup and Traps:** The master script installs a trap to attempt cleanup on error.

---

### 1. **auto_env_setup.sh**  
_Sets up a RAM‑based workspace and verifies dependencies._

```bash
#!/bin/bash
# auto_env_setup.sh
# Sets up a RAM-based secure workspace for all subsequent operations.
# Checks for required commands.
#
# Requirements: mount, mkdir, iptables (if used)

set -euo pipefail

# Dependency check function
function require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo >&2 "Error: $1 is required but not installed. Aborting."; exit 1; }
}

echo "[*] Checking dependencies..."
for cmd in mount mkdir iptables; do
    require_cmd "$cmd"
done

echo "[*] Setting up secure environment..."

SECURE_WORKSPACE="/mnt/secure_workspace"
if ! mountpoint -q "$SECURE_WORKSPACE"; then
    sudo mkdir -p "$SECURE_WORKSPACE"
    sudo mount -t tmpfs -o size=2G tmpfs "$SECURE_WORKSPACE"
    echo "[*] Secure workspace mounted at $SECURE_WORKSPACE"
else
    echo "[*] Secure workspace already mounted at $SECURE_WORKSPACE"
fi

cd "$SECURE_WORKSPACE"

# (Optional: Add iptables rules here if desired.)
# Example (uncomment and modify as needed):
# TRUSTED_IPS=("1.2.3.4" "5.6.7.8")
# echo "[*] Configuring iptables to allow only trusted hosts..."
# sudo iptables -F
# sudo iptables -P INPUT DROP
# sudo iptables -P OUTPUT DROP
# sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# for ip in "${TRUSTED_IPS[@]}"; do
#     sudo iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -d "$ip" -j ACCEPT
# done

echo "[*] Environment setup complete."
```

---

### 2. **auto_download.sh**  
_Downloads and verifies Parrot OS and BlackArch ISOs plus checksum and signature files. Replace the placeholder URLs with trusted ones._

```bash
#!/bin/bash
# auto_download.sh
# Downloads OS images and verification files and verifies them.
#
# Requirements: curl, sha256sum, gpg
# Replace URL placeholders with your trusted mirror locations.

set -euo pipefail

# Dependency checks
for cmd in curl sha256sum gpg; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd is not installed."; exit 1; }
done

echo "[*] Downloading OS images and verification files..."

# --- Parrot OS Variables ---
PARROT_ISO_URL="https://trusted-mirror.example.com/parrot.iso"
PARROT_SHA256_URL="https://trusted-mirror.example.com/parrot.iso.sha256"
PARROT_SIG_URL="https://trusted-mirror.example.com/parrot.iso.sig"

echo "[*] Downloading Parrot OS ISO..."
curl --fail -sSL -o parrot.iso "$PARROT_ISO_URL"
curl --fail -sSL -o parrot.iso.sha256 "$PARROT_SHA256_URL"
curl --fail -sSL -o parrot.iso.sig "$PARROT_SIG_URL"

# --- BlackArch Variables ---
BLACKARCH_ISO_URL="https://trusted-mirror.example.com/blackarch.iso"
BLACKARCH_SHA256_URL="https://trusted-mirror.example.com/blackarch.iso.sha256"
BLACKARCH_SIG_URL="https://trusted-mirror.example.com/blackarch.iso.sig"

echo "[*] Downloading BlackArch ISO..."
curl --fail -sSL -o blackarch.iso "$BLACKARCH_ISO_URL"
curl --fail -sSL -o blackarch.iso.sha256 "$BLACKARCH_SHA256_URL"
curl --fail -sSL -o blackarch.iso.sig "$BLACKARCH_SIG_URL"

echo "[*] Verifying Parrot OS ISO checksum..."
sha256sum -c parrot.iso.sha256

echo "[*] Verifying Parrot OS GPG signature..."
gpg --batch --verify parrot.iso.sig parrot.iso

echo "[*] Verifying BlackArch ISO checksum..."
sha256sum -c blackarch.iso.sha256

echo "[*] Verifying BlackArch GPG signature..."
gpg --batch --verify blackarch.iso.sig blackarch.iso

echo "[*] Download and verification complete."
```

---

### 3. **auto_partition.sh**  
_Non‑interactively partitions **/dev/sdc** using the specified layout. This script unmounts any mounted partitions first._

```bash
#!/bin/bash
# auto_partition.sh
# Partitions /dev/sdc as follows:
#   Partition 1 (EFI): from 1MiB to 191MiB (~190 MiB)
#   Partition 2 (Parrot OS): from 191MiB to 3791MiB (~3.6GiB)
#   Partition 3 (BlackArch): from 3791MiB to 100% (~3.7GiB)
#
# Requirements: parted, lsblk
# WARNING: This will DESTROY all data on /dev/sdc.

set -euo pipefail

USB_DEVICE="/dev/sdc"
echo "[*] WARNING: This will completely erase $USB_DEVICE."
echo "[*] Proceeding with partitioning $USB_DEVICE without intervention..."

# Unmount any mounted partitions on /dev/sdc
for part in $(lsblk -ln -o NAME "$USB_DEVICE" | tail -n +2); do
    sudo umount "/dev/$part" 2>/dev/null || true
done

echo "[*] Creating a new GPT partition table on $USB_DEVICE..."
sudo parted "$USB_DEVICE" --script mklabel gpt

echo "[*] Creating EFI partition (1MiB to 191MiB)..."
sudo parted "$USB_DEVICE" --script mkpart ESP fat32 1MiB 191MiB
sudo parted "$USB_DEVICE" --script set 1 esp on

echo "[*] Creating Parrot OS partition (191MiB to 3791MiB)..."
sudo parted "$USB_DEVICE" --script mkpart primary ext4 191MiB 3791MiB

echo "[*] Creating BlackArch partition (3791MiB to 100%)..."
sudo parted "$USB_DEVICE" --script mkpart primary ext4 3791MiB 100%

echo "[*] Partitioning complete. New layout:"
lsblk "$USB_DEVICE"
```

---

### 4. **auto_write_isos.sh**  
_Writes the downloaded ISO images onto the correct partitions using dd with fsync, then forces a sync._

```bash
#!/bin/bash
# auto_write_isos.sh
# Writes the downloaded ISOs to partitions:
#   - Parrot OS to /dev/sdc2
#   - BlackArch to /dev/sdc3
#
# Requirements: dd, sync

set -euo pipefail

USB_DEVICE="/dev/sdc"

echo "[*] Writing Parrot OS ISO to ${USB_DEVICE}2..."
sudo dd if=parrot.iso of="${USB_DEVICE}2" bs=4M status=progress conv=fsync
sudo sync

echo "[*] Writing BlackArch ISO to ${USB_DEVICE}3..."
sudo dd if=blackarch.iso of="${USB_DEVICE}3" bs=4M status=progress conv=fsync
sudo sync

echo "[*] ISO writing complete."
```

---

### 5. **auto_install_refind.sh**  
_Installs rEFInd non‑interactively onto the EFI partition (assumed to be /dev/sdc1). Replace the URL with a trusted source. Additional optional signing steps are provided._

```bash
#!/bin/bash
# auto_install_refind.sh
# Downloads and installs rEFInd onto the EFI partition (/dev/sdc1) non-interactively.
#
# Requirements: curl, chattr, bash
# Replace REFIND_URL with your trusted installer location.

set -euo pipefail

USB_DEVICE="/dev/sdc"
EFI_PART="${USB_DEVICE}1"
EFI_MOUNT="/mnt/efi"

echo "[*] Mounting EFI partition (${EFI_PART})..."
sudo mkdir -p "$EFI_MOUNT"
sudo mount "$EFI_PART" "$EFI_MOUNT"

echo "[*] Downloading rEFInd installer..."
REFIND_URL="https://trusted-source.example.com/refind-install.sh"
refind_script=$(curl --fail -sSL "$REFIND_URL")

# Optional: add integrity verification for refind_script here (e.g. SHA256 or GPG)

echo "[*] Installing rEFInd..."
# Pipe the script directly to bash; using --yes to avoid prompts and specifying the root.
echo "$refind_script" | sudo bash -s -- --yes --root "$EFI_MOUNT"

echo "[*] (Optional) Signing rEFInd binary for Secure Boot..."
# Uncomment and modify the following lines if you have signing keys:
# sudo sbsign --key /path/to/db.key --cert /path/to/db.crt \
#    --output "$EFI_MOUNT/EFI/refind/refind_x64.efi" \
#    "$EFI_MOUNT/EFI/refind/refind_x64.efi"

echo "[*] Setting immutable attributes on critical rEFInd files..."
sudo chattr +i "$EFI_MOUNT/EFI/refind/refind.conf" 2>/dev/null || echo "[!] Warning: Could not set immutable flag on refind.conf"
sudo chattr +i "$EFI_MOUNT/EFI/refind/refind_x64.efi" 2>/dev/null || echo "[!] Warning: Could not set immutable flag on refind_x64.efi"

sudo umount "$EFI_MOUNT"
echo "[*] rEFInd installation complete."
```

---

### 6. **auto_cleanup.sh**  
_Cleans up the secure workspace and resets any temporary network changes if you applied them._

```bash
#!/bin/bash
# auto_cleanup.sh
# Cleans up the secure in-RAM workspace and resets network rules (if modified).
#
# Requirements: umount, rm, iptables

set -euo pipefail

echo "[*] Cleaning up secure environment..."

SECURE_WORKSPACE="/mnt/secure_workspace"
if mountpoint -q "$SECURE_WORKSPACE"; then
    sudo umount "$SECURE_WORKSPACE"
    sudo rm -rf "$SECURE_WORKSPACE"
    echo "[*] Secure workspace removed."
else
    echo "[*] No secure workspace found to remove."
fi

# (Optional) Reset iptables to defaults if modified:
# echo "[*] Resetting iptables rules..."
# sudo iptables -F
# sudo iptables -P INPUT ACCEPT
# sudo iptables -P OUTPUT ACCEPT
# sudo iptables -P FORWARD ACCEPT

echo "[*] Cleanup complete."
```

---

### 7. **auto_master.sh**  
_The master script calls all the above scripts in order. A trap is installed to attempt cleanup on error._

```bash
#!/bin/bash
# auto_master.sh
# Master script to run the complete automated USB setup on /dev/sdc.
#
# Run as root; this script will call all others non-interactively.

set -euo pipefail

TARGET_DEVICE="/dev/sdc"
echo "[*] Starting fully automated USB setup on ${TARGET_DEVICE}..."

# Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo $0)."
  exit 1
fi

# Trap errors to attempt cleanup.
trap 'echo "[!] An error occurred. Running cleanup..."; bash auto_cleanup.sh; exit 1' ERR

# Step 1: Environment Setup
bash auto_env_setup.sh

# Step 2: Download and Verify OS Images
bash auto_download.sh

# Step 3: Partition the USB device (/dev/sdc)
bash auto_partition.sh

# Step 4: Write the OS ISOs to partitions
bash auto_write_isos.sh

# Step 5: Install rEFInd onto the EFI partition
bash auto_install_refind.sh

# Step 6: Cleanup the environment
bash auto_cleanup.sh

echo "[*] Fully automated USB setup on ${TARGET_DEVICE} complete."
```

---

### **Usage Instructions**

1. **Prepare Your Environment:**  
   - Boot from a trusted, verified live OS (such as Tails or a known-good SystemRescue USB).  
   - Verify that **/dev/sdc** is the target USB device.

2. **Place All Scripts in One Directory:**  
   For example, in `/root/usb_setup/`.

3. **Make Them Executable:**
   ```bash
   chmod +x auto_env_setup.sh auto_download.sh auto_partition.sh auto_write_isos.sh auto_install_refind.sh auto_cleanup.sh auto_master.sh
   ```

4. **Run the Master Script as Root:**
   ```bash
   sudo ./auto_master.sh
   ```

---

These revised scripts should work in sequence with minimal (ideally zero) manual intervention. They now incorporate extra error checking, logging, and cleanup steps to help ensure a more robust and secure USB setup. Always test on expendable hardware first and adjust the details (especially URLs and device names) to fit your trusted environment and threat model.
