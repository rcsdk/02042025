#!/bin/bash

# Log file for tracking the script execution
LOG_FILE="/var/log/ssh_hardening_script.log"

# Function to log and display messages
log_message() {
    echo "$1"
    echo "$(date): $1" >> "$LOG_FILE"
}

# Step 1: Harden SSH Configuration
log_message "Hardening SSH configuration"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    # Backup the current SSH config file
    cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak"
    log_message "Backup of /etc/ssh/sshd_config created."

    # Disable root login, require key-based authentication, etc.
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sed -i 's/^#AllowUsers.*/AllowUsers yourtrusteduser/' "$SSHD_CONFIG"
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
    sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
    sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' "$SSHD_CONFIG"
    sed -i 's/^#X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"
    sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' "$SSHD_CONFIG"
    sed -i '/^Subsystem sftp /s/^/#/' "$SSHD_CONFIG"
    sed -i 's/^#AddressFamily.*/AddressFamily inet/' "$SSHD_CONFIG"

    log_message "SSH configuration updated."
else
    log_message "ERROR: /etc/ssh/sshd_config not found!"
    exit 1
fi

# Step 2: Disable IPv6
log_message "Disabling IPv6"

# Create a sysctl file to disable IPv6
SYSCTL_CONF="/etc/sysctl.d/99-disable-ipv6.conf"
echo -e "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" > "$SYSCTL_CONF"

# Apply the sysctl settings
sysctl -p "$SYSCTL_CONF"
log_message "IPv6 has been disabled."

# Step 3: Configure Firewall Rules
log_message "Configuring firewall rules for SSH access"

# Allow SSH only from specific IP (replace <trusted_ip> with your trusted IP address)
FIREWALL_CMD="sudo ufw allow from <trusted_ip> to any port 22"
$FIREWALL_CMD

log_message "Firewall rules updated to allow SSH from trusted IP."

# Step 4: Install and Configure Fail2Ban
log_message "Installing and configuring Fail2Ban"

# Install fail2ban if not already installed
if ! command -v fail2ban-client &> /dev/null; then
    apt-get update && apt-get install -y fail2ban
    log_message "fail2ban installed."
else
    log_message "fail2ban is already installed."
fi

# Enable and start fail2ban service
systemctl enable --now fail2ban
log_message "fail2ban service started and enabled."

# Configure fail2ban to protect SSH
echo -e "[sshd]\nenabled = true\nport = ssh\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime = 3600\nfindtime = 600" > /etc/fail2ban/jail.d/sshd.conf

# Restart fail2ban to apply the new configuration
systemctl restart fail2ban
log_message "Fail2Ban configured to protect SSH."

# Step 5: Restart SSH Service
log_message "Restarting SSH service"
systemctl restart sshd
log_message "SSH service restarted."

# Summary Table
log_message "Security configuration changes completed."
echo "------------------------------------------------------"
echo "| Config Item                     | Status           |"
echo "|----------------------------------|------------------|"
echo "| Root Login                      | Disabled         |"
echo "| Password Authentication         | Disabled         |"
echo "| Empty Passwords                 | Disabled         |"
echo "| TCP Forwarding                  | Disabled         |"
echo "| X11 Forwarding                  | Disabled         |"
echo "| IPv6                           | Disabled         |"
echo "| Firewall Rule for SSH           | Configured       |"
echo "| Fail2Ban                        | Installed & Active |"
echo "------------------------------------------------------"

# End of script











# Disable IPv6
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p  # Apply changes immediately

# Disable SSH root login
sudo sed -i 's/^#PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# Disable SSH password authentication (key-based auth only)
sudo sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Disable SSH protocol version 1 (just in case)
sudo sed -i 's/^#Protocol .*/Protocol 2/' /etc/ssh/sshd_config

# Disable unused services and ensure SSH won't start on boot if not needed
sudo systemctl stop sshd  # Stop the SSH service immediately
sudo systemctl disable sshd  # Disable SSH on boot

# Reload SSH configuration to apply changes
sudo systemctl reload sshd

# If you want to ensure SSH is disabled and the server won't start it on boot, check it with:
# sudo systemctl status sshd

# Optional: Disable other network services or firewalls as needed
# For example, you can add a firewall rule to block incoming SSH traffic:
# sudo ufw deny ssh
# Disable IPv6
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p  # Apply changes immediately

# Disable SSH root login
sudo sed -i 's/^#PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

# Disable SSH password authentication (key-based auth only)
sudo sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Disable SSH protocol version 1 (just in case)
sudo sed -i 's/^#Protocol .*/Protocol 2/' /etc/ssh/sshd_config

# Disable unused services and ensure SSH won't start on boot if not needed
sudo systemctl stop sshd  # Stop the SSH service immediately
sudo systemctl disable sshd  # Disable SSH on boot

# Reload SSH configuration to apply changes
sudo systemctl reload sshd

# If you want to ensure SSH is disabled and the server won't start it on boot, check it with:
# sudo systemctl status sshd

# Optional: Disable other network services or firewalls as needed
# For example, you can add a firewall rule to block incoming SSH traffic:
# sudo ufw deny ssh




#!/bin/bash

# Variables
SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONFIG="/etc/sysctl.conf"

# Disable IPv6
echo "Disabling IPv6..."
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a $SYSCTL_CONFIG
echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a $SYSCTL_CONFIG
echo "net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a $SYSCTL_CONFIG
sudo sysctl -p  # Apply changes immediately

# Backup existing SSH config (just in case)
echo "Backing up current SSH config..."
sudo cp $SSHD_CONFIG ${SSHD_CONFIG}.bak

# Create a new, secure SSH config
echo "Creating a new, secure SSH config..."
sudo bash -c "cat > $SSHD_CONFIG" <<EOF
# Secure SSH Config

# Disable root login
PermitRootLogin no

# Disable password authentication
PasswordAuthentication no

# Allow only key-based login
PubkeyAuthentication yes

# Disable unused protocols
Protocol 2

# Allow only certain users (change 'user' to your actual user)
AllowUsers user

# Disable SSH for other users
DenyUsers root

# Disable SSH agent forwarding
AllowAgentForwarding no

# Limit access to specific IPs if needed (uncomment and edit for your needs)
# ListenAddress 192.168.1.100

# Set SSH port (optional, you can change this if needed)
Port 22
EOF

# Reload SSH service to apply changes
echo "Reloading SSH service to apply changes..."
sudo systemctl reload sshd

# Disable SSH service on boot (if you don't need it)
echo "Disabling SSH service on boot..."
sudo systemctl stop sshd
sudo systemctl disable sshd

# Display status of SSH service
echo "Checking status of SSH service..."
sudo systemctl status sshd

echo "Security hardening completed!"




Updated Secure /etc/ssh/sshd_config Configuratio
sudo nano /etc/ssh/sshd_config
sudo systemctl restart sshd
sudo systemctl status sshd




# Include drop-in configurations
Include /etc/ssh/sshd_config.d/*.conf

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# Disable root login
PermitRootLogin no

# Allow only specific users to login (modify 'user' with actual usernames)
AllowUsers user

# Disable password authentication (only allow key-based login)
PasswordAuthentication no

# Disable empty passwords
PermitEmptyPasswords no

# Disable challenge-response authentication
ChallengeResponseAuthentication no

# Disable unused protocols
Protocol 2

# Use key-based authentication only
PubkeyAuthentication yes

# Allow only specific IPs to access SSH (optional)
# ListenAddress 192.168.1.100  # Uncomment and modify this line for restricted IP access

# Disable SSH agent forwarding for additional security
AllowAgentForwarding no

# Configure max auth attempts (optional)
MaxAuthTries 3

# Specify a custom port (optional, change to something other than 22 for additional security)
Port 22

# Disable unused subsystems
Subsystem sftp /usr/lib/ssh/sftp-server









#!/bin/bash

# Log file for tracking the script execution
LOG_FILE="/var/log/ssh_hardening_script.log"

# Function to log and display messages
log_message() {
    echo "$1"
    echo "$(date): $1" >> "$LOG_FILE"
}

# Step 1: Harden SSH Configuration
log_message "Hardening SSH configuration"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    # Backup the current SSH config file
    cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak"
    log_message "Backup of /etc/ssh/sshd_config created."

    # Disable root login, require key-based authentication, etc.
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sed -i 's/^#AllowUsers.*/AllowUsers yourtrusteduser/' "$SSHD_CONFIG"
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
    sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
    sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' "$SSHD_CONFIG"
    sed -i 's/^#X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"
    sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' "$SSHD_CONFIG"
    sed -i '/^Subsystem sftp /s/^/#/' "$SSHD_CONFIG"
    sed -i 's/^#AddressFamily.*/AddressFamily inet/' "$SSHD_CONFIG"

    log_message "SSH configuration updated."
else
    log_message "ERROR: /etc/ssh/sshd_config not found!"
    exit 1
fi

# Step 2: Disable IPv6
log_message "Disabling IPv6"

# Create a sysctl file to disable IPv6
SYSCTL_CONF="/etc/sysctl.d/99-disable-ipv6.conf"
echo -e "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" > "$SYSCTL_CONF"

# Apply the sysctl settings
sysctl -p "$SYSCTL_CONF"
log_message "IPv6 has been disabled."

# Step 3: Configure Firewall Rules
log_message "Configuring firewall rules for SSH access"

# Allow SSH only from specific IP (replace <trusted_ip> with your trusted IP address)
FIREWALL_CMD="sudo ufw allow from <trusted_ip> to any port 22"
$FIREWALL_CMD

log_message "Firewall rules updated to allow SSH from trusted IP."

# Step 4: Install and Configure Fail2Ban
log_message "Installing and configuring Fail2Ban"

# Install fail2ban if not already installed
if ! command -v fail2ban-client &> /dev/null; then
    apt-get update && apt-get install -y fail2ban
    log_message "fail2ban installed."
else
    log_message "fail2ban is already installed."
fi

# Enable and start fail2ban service
systemctl enable --now fail2ban
log_message "fail2ban service started and enabled."

# Configure fail2ban to protect SSH
echo -e "[sshd]\nenabled = true\nport = ssh\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime = 3600\nfindtime = 600" > /etc/fail2ban/jail.d/sshd.conf

# Restart fail2ban to apply the new configuration
systemctl restart fail2ban
log_message "Fail2Ban configured to protect SSH."

# Step 5: Restart SSH Service
log_message "Restarting SSH service"
systemctl restart sshd
log_message "SSH service restarted."

# Summary Table
log_message "Security configuration changes completed."
echo "------------------------------------------------------"
echo "| Config Item                     | Status           |"
echo "|----------------------------------|------------------|"
echo "| Root Login                      | Disabled         |"
echo "| Password Authentication         | Disabled         |"
echo "| Empty Passwords                 | Disabled         |"
echo "| TCP Forwarding                  | Disabled         |"
echo "| X11 Forwarding                  | Disabled         |"
echo "| IPv6                           | Disabled         |"
echo "| Firewall Rule for SSH           | Configured       |"
echo "| Fail2Ban                        | Installed & Active |"
echo "------------------------------------------------------"

# End of script

	

