#!/bin/bash
# Create backup directory if it doesn't exist
mkdir -p /mnt/1/session/.session-store
mkdir -p /mnt/1/session/.session-store/backups

# Create timestamped backup with simple format (MM_DD)
timestamp=$(date +%m_%d)
mkdir -p /mnt/1/session/.session-store/backups/session_$timestamp
cp -r /mnt/1/session/.session-store/* /mnt/1/session/.session-store/backups/session_$timestamp/

# Verify the backup
ls -la /mnt/1/session/.session-store/backups/
