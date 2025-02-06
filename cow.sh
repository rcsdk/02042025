#!/bin/bash

# Step 1: Ensure cowsspace is writable
echo "Ensuring cowspace is writable..."
sudo mount -o remount,rw /run/archiso/cowspace

# Step 2: Set immutable attribute on cowsspace
echo "Setting immutable attribute on /run/archiso/cowspace..."
sudo chattr +i /run/archiso/cowspace

# Step 3: Set immutable attribute on persistent_RESCUE1103
echo "Setting immutable attribute on /run/archiso/cowspace/persistent_RESCUE1103..."
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103

# Step 4: Set immutable attribute on specific directories within persistent_RESCUE1103
echo "Setting immutable attribute on /run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir..."
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103/x86_64/upperdir
echo "Setting immutable attribute on /run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir..."
sudo chattr +i /run/archiso/cowspace/persistent_RESCUE1103/x86_64/workdir

# Step 5: Set immutable attribute on the tmpfs mount point
echo "Setting immutable attribute on /run/archiso/cowspace..."
sudo chattr +i /run/archiso/cowspace

# Step 6: Ensure the backup directory exists
BACKUP_DIR="/mnt/backup"
echo "Ensuring backup directory exists at $BACKUP_DIR..."
sudo mkdir -p $BACKUP_DIR

# Step 7: Add cron job for daily backup
CRON_JOB="0 1 * * * rsync -av /run/archiso/cowspace $BACKUP_DIR"
echo "Adding cron job for daily backup at 1:00 AM..."
(crontab -l 2>/dev/null; echo "$CRON_JOB") | sudo crontab -

# Step 8: Verify cron job
echo "Verifying cron job..."
sudo crontab -l

echo "Script completed. Cowspace is secured and a daily backup is scheduled."
