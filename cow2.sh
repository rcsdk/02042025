#!/bin/bash

# Step 1: Install SELinux and necessary packages
echo "Installing SELinux and necessary packages..."
sudo pacman -S --noconfirm selinux refpolicy checkpolicy inotify-tools

# Step 2: Generate SELinux Policy
echo "Generating SELinux policy..."
cd /tmp
git clone https://github.com/SELinuxProject/refpolicy.git
cd refpolicy
make -j$(nproc)
make install

# Step 3: Enable SELinux
echo "Enabling SELinux..."
sudo selinux-activate
sudo setenforce 1
sudo sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config

# Step 4: Apply SELinux Contexts
echo "Applying SELinux contexts to cowspace and persistent_RESCUE1103..."
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace(/.*)?"
sudo restorecon -Rv /run/archiso/cowspace
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace/persistent_RESCUE1103(/.*)?"
sudo restorecon -Rv /run/archiso/cowspace/persistent_RESCUE1103
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir(/.*)?"
sudo semanage fcontext -a -t tmpfs_t "/run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir(/.*)?"
sudo restorecon -Rv /run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir
sudo restorecon -Rv /run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir

# Step 5: Set Immutable Attribute
echo "Setting immutable attribute on cowsspace and its components..."
sudo chattr +i /run/archiso/cowspace
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir

# Step 6: Monitor for Changes
echo "Setting up inotify-tools to monitor changes..."
sudo inotifywait -m -r -e modify,delete,create,attrib /run/archiso/cowspace &

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

echo "Script completed. SELinux is configured, cowspace is secured, and a daily backup is scheduled."
