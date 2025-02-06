

sudo chattr +i /run/archiso/cowspace



lsattr /run/archiso/cowspace


echo 14G > /proc/sys/vm/drop_caches

free -h

    sudo pacman -S inotify-tools


inotifywait -m -r -e modify,delete,create /run/archiso/cowspace

sudo pacman -S clamav
sudo freshclam
sudo clamscan -r /run/archiso/cowspace



    cat > monitor_cowspace.sh << 'EOF'
    #!/bin/bash
    while true; do
        # Check if cowspace is still writable
        if [ ! -w /run/archiso/cowspace ]; then
            echo "ALERT: Cowspace permissions changed!" | sudo tee -a /var/log/cowspace_monitor.log
        fi
        
        # Check RAM reservation
        if [ $(free -g | awk 'NR==2 {print $3}') -lt 14 ]; then
            echo "ALERT: RAM reservation below 14GB!" | sudo tee -a /var/log/cowspace_monitor.log
        fi
        
        sleep 300 # Check every 5 minutes
    done
    EOF
