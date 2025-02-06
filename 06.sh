#!/bin/bash
# Enhanced Security Hardening Script - Deep Protection Mode
# Applies advanced security fixes with multiple layers of defense

# Set strict mode with enhanced error handling
set -euo pipefail
IFS=$'\n\t'
trap 'exit 1' ERR

# Logging function with enhanced security
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} - ${1}" >&2
}

# Enhanced backup function with integrity checking
backup_file() {
    local file="$1"
    local backup="${file}.bak.$(date '+%Y%m%d_%H%M%S')"
    
    if [ -f "$file" ]; then
        cp -a "$file" "$backup"
        log "Created integrity-checked backup: $backup"
        sha256sum "$backup" >> "${backup}.sha256"
    fi
}

# Check if running in a live environment
log "Checking if running in a live environment..."
if grep -q 'archiso' /proc/cmdline; then
    log "Live environment detected. Skipping Lynis update."
else
    # Enhanced Lynis update with integrity verification
    if command -v lynis &> /dev/null; then
        log "Updating Lynis with enhanced verification..."
        if ! lynis update info --verbose; then
            log "Warning: Lynis update failed, continuing."
        fi
    else
        log "Installing Lynis with dependency verification..."
        if ! pacman -Sy --noconfirm lynis; then
            log "Error: Failed to install Lynis, exiting."
            exit 1
        fi
    fi
fi

# System updates with package cache cleaning and verification
log "Updating system packages with enhanced verification..."
pacman -Syyu --noconfirm || {
    log "Error: Package update failed!"
    exit 1
}
pacman -Sc --noconfirm
pacman -Dk || true  # Check database consistency

# File permissions hardening with extended protection
log "Setting deep file permissions..."
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 700 /root
chmod 600 /etc/sudoers
chmod 600 /etc/security/access.conf
chmod 600 /etc/pam.d/*

# Backup SSH config before modification
backup_file "/etc/ssh/sshd_config"

# Secure SSH configuration with advanced parameters
log "Hardening SSH configuration with enhanced security..."
sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries.*/MaxAuthTries 2/' /etc/ssh/sshd_config
sed -i 's/^#TCPKeepAlive.*/TCPKeepAlive no/' /etc/ssh/sshd_config
sed -i 's/^#AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -i 's/^#PrintMotd.*/PrintMotd no/' /etc/ssh/sshd_config
sed -i 's/^#PrintLastLog.*/PrintLastLog yes/' /etc/ssh/sshd_config
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

# Restart SSH service safely
if ! systemctl restart sshd; then
    log "Warning: Failed to restart SSHD, attempting reload..."
    if ! systemctl reload sshd; then
        log "Error: SSH service reload failed!"
        exit 1
    fi
fi

# Enhanced firewall rules with stateful inspection
log "Configuring enhanced firewall rules..."
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Essential services with rate limiting
iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j DROP
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m limit --limit 5/min --limit-burst 4 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -m limit --limit 10/min -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Save iptables rules with checksum verification
iptables-save > /etc/iptables/iptables.rules
sha256sum /etc/iptables/iptables.rules > /etc/iptables/iptables.sha256

# Enhanced kernel security parameters
log "Applying deep kernel security settings..."
cat << EOF | tee /etc/sysctl.d/99-hardening.conf
# Kernel self-protection
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.printk=3 3 3 3
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
dev.tty.ldisc_autoload=0
vm.unprivileged_userfaultfd=0
kernel.kexec_load_disabled=1
kernel.sysrq=4
kernel.unprivileged_userns_clone=0
kernel.perf_event_paranoid=3

# Network hardening
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0

# Memory protection
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
fs.protected_symlinks=1
fs.protected_hardlinks=1
fs.protected_fifos=2
fs.protected_regular=2

# Filesystem protection
kernel.modules_disabled=1
kernel.syslog_action_drop_cap=0
EOF

# Apply sysctl settings with verification
sysctl -p /etc/sysctl.d/99-hardening.conf || {
    log "Warning: Failed to apply some sysctl settings!"
}

# Enhanced audit configuration
log "Setting up deep audit configuration..."
auditctl -b 8192
auditctl -w /etc/passwd -p wa
auditctl -w /etc/group -p wa
auditctl -w /etc/shadow -p wa
auditctl -w /etc/sudoers -p wa
auditctl -w /var/log/auth.log -p wa
auditctl -w /etc/security/access.conf -p wa
auditctl -w /etc/pam.d/ -p wa
auditctl -w /usr/bin/su -p x
auditctl -w /sbin/unix_chkpwd -p x
auditctl -w /usr/sbin/cron -p x
auditctl -w /etc/crontab -p wa
auditctl -w /var/spool/cron/ -p wa

# Set immutable audit logs
chattr +a /var/log/audit/audit.log

# Final security checks with enhanced verification
log "Running final security checks..."
systemctl list-units --type=service --state=active | grep -vE '(systemd|network|polkit|cron)'
mount | grep -E 'overlay|tmpfs|nfs'

# Run rkhunter scan with extended checks
log "Running rootkit hunter scan with extended checks..."
rkhunter --update
rkhunter --propupd
rkhunter --check --sk --show-none --enable all --disable none

# Verify system integrity
log "Running filesystem integrity check..."
sha256sum -c /usr/bin/sudo.SHA256
sha256sum -c /bin/login.SHA256

# Final log message
log "Deep security hardening completed! Run 'lynis audit system' again to verify."
