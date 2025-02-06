#!/bin/bash

# Function to check if a package is installed
is_installed() {
    pacman -Q "$1" &> /dev/null
}

# Function to install packages with fallback to curl or wget
install_packages() {
    for package in "$@"; do
        if ! is_installed "$package"; then
            echo "Installing $package..."
            sudo pacman -S --noconfirm "$package"
        else
            echo "$package is already installed."
        fi
    done
}

# Step 1: Fix pacman and libcurl issues
echo "Fixing pacman and libcurl issues..."
sudo pacman-key --init
sudo pacman-key --populate archlinux
sudo pacman -Syu --noconfirm

# Step 2: Install necessary packages
echo "Checking and installing required packages..."
install_packages acl inotify-tools rsync curl git base-devel

# Check if wget is installed, if not, install it
if ! is_installed wget; then
    echo "Checking if wget is installed..."
    sudo pacman -S --noconfirm wget
fi

# Step 3: Ensure cowsspace is writable
echo "Ensuring cowsspace is writable..."
sudo mount -o remount,rw /run/archiso/cowspace

# Step 4: Set immutable attribute on cowsspace
echo "Setting immutable attribute on /run/archiso/cowspace..."
sudo chattr +i /run/archiso/cowspace

# Step 5: Set immutable attribute on persistent_RESCUE1103
echo "Setting immutable attribute on /run/archiso/cowspace/persistent_RESCUE1103..."
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103

# Step 6: Set immutable attribute on specific directories within persistent_RESCUE1103
echo "Setting immutable attribute on /run/archiso/cowspace/persistent_RESCUE1103/x8a6_64/upperdir..."
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir
echo "Setting immutable attribute on /run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir..."
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir

# Step 7: Ensure the backup directory exists
BACKUP_DIR="/mnt/backup"
echo "Ensuring backup directory exists at $BACKUP_DIR..."
sudo mkdir -p $BACKUP_DIR

# Step 8: Add cron job for daily backup
CRON_JOB="0 1 * * * rsync -av /run/archiso/cowspace $BACKUP_DIR"
echo "Adding cron job for daily backup at 1:00 AM..."
(crontab -l 2>/dev/null; echo "$CRON_JOB") | sudo crontab -

# Step 9: Verify cron job
echo "Verifying cron job..."
sudo crontab -l

# Step 10: Install SELinux and necessary packages
echo "Installing SELinux and necessary packages..."
install_packages selinux refpolicy checkpolicy

# Step 11: Enable SELinux
echo "Enabling SELinux..."
sudo selinux-activate
sudo setenforce 1
sudo sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config

# Step 12: Apply SELinux Contexts
echo "Applying SELinux contexts to cowspace and persistent_RESCUE1103..."
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace(/.*)?"
sudo restorecon -Rv /run/archiso/cowspace
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace/persistent_RESCUE1103(/.*)?"
sudo restorecon -Rv /run/archiso/cowspace/persistent_RESCUE1103
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir(/.*)?"
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir(/.*)?"
sudo restorecon -Rv /run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir
sudo restorecon -Rv /run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir

# Step 13: Monitor for Changes
echo "Setting up inotify-tools to monitor changes..."
sudo inotifywait -m -r -e modify,delete,create,attrib /run/archiso/cowspace &

# Step 14: Rebuild necessary packages with SELinux support
echo "Rebuilding necessary packages with SELinux support..."

# Function to rebuild a package with SELinux support
rebuild_package() {
    local package="$1"
    local flags="$2"
    echo "Rebuilding $package with flags: $flags..."
    if ! is_installed "$package"; then
        echo "$package is not installed. Skipping rebuild."
        return
    fi

    # Clone the package from AUR
    git clone "https://aur.archlinux.org/$package.git"
    cd "$package" || return

    # Apply SELinux flags to PKGBUILD
    sed -i "/configure/a \\\n    $flags" PKGBUILD

    # Build and install the package
    makepkg -si --noconfirm

    # Clean up
    cd ..
    rm -rf "$package"
}

# Rebuild packages with SELinux support
rebuild_package coreutils "--with-selinux"
rebuild_package cronie "--with-selinux"
rebuild_package dbus "--enable-libaudit --enable-selinux"
rebuild_package findutils ""
rebuild_package iproute2 "--with-selinux"
rebuild_package logrotate "--with-selinux"
rebuild_package openssh "--with-selinux"
rebuild_package pam "--enable-selinux"
rebuild_package pambase ""
rebuild_package psmisc "--with-selinux"
rebuild_package shadow "--with-selinux"
rebuild_package sudo "--with-selinux"
rebuild_package systemd "--enable-audit --enable-selinux"
rebuild_package util-linux "--with-selinux"

# Step 15: Rebuild Linux kernel with SELinux support
echo "Rebuilding Linux kernel with SELinux support..."

# Clone the Linux kernel package from Arch Linux GitLab
git clone "https://gitlab.archlinux.org/archlinux/packaging/packages/linux.git"
cd linux || exit

# Apply SELinux flags to PKGBUILD
sed -i '/linux-vanilla/a \\\n    lsm=selinux' PKGBUILD

# Build and install the package
makepkg -si --noconfirm

# Clean up
cd ..
rm -rf linux

echo "Script completed. SELinux is configured, cowspace is secured, and a daily backup is scheduled."
