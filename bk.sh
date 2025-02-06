#!/bin/bash
# Create session directory if it doesn't exist
mkdir -p /mnt/1/session/.session-store

# List available backups
echo "Available backups (format: MM_DD):"
ls -la /mnt/1/session/.session-store/backups/

# Ask for timestamp
read -p "Enter backup date (e.g., 02_01 for Feb 1st): " timestamp

# Restore the selected backup
if [ -d "/mnt/1/session/.session-store/backups/session_$timestamp" ]; then
    cp -r /mnt/1/session/.session-store/backups/session_$timestamp/* /mnt/1/session/.session-store/
    echo "Restored from backup $timestamp"
else
    echo "Backup not found!"
fi
