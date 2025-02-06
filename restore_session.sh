#!/bin/bash
# List available backups
echo "Available backups:"
ls -la /mnt/1/session/.session-store/backups/

# Ask for timestamp
read -p "Enter backup timestamp (e.g., 20250206_180850): " timestamp

# Restore the selected backup
if [ -d "/mnt/1/session/.session-store/backups/session_$timestamp" ]; then
    cp -r /mnt/1/session/.session-store/backups/session_$timestamp/* /mnt/1/session/.session-store/
    echo "Restored from backup $timestamp"
else
    echo "Backup not found!"
fi
