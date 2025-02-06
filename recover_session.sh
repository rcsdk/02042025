#!/bin/bash
# Wait for USB to be recognized
sleep 10

# Check if previous session was interrupted
if [ -f /mnt/1/session/.session-store/crash/recovering ]; then
    # Restore from last known good state
    cp -r /mnt/1/session/.session-store/crash/last_session/* /mnt/1/session/.session-store/
    rm /mnt/1/session/.session-store/crash/recovering
fi

# Create crash marker for next boot
touch /mnt/1/session/.session-store/crash/recovering
chmod 644 /mnt/1/session/.session-store/crash/recovering

# Update session links
ln -sf /mnt/1/session/.session-store ~/.session-store
ln -sf /mnt/1/session/.cache/sessions ~/.cache/sessions
