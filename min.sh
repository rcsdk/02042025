#!/bin/bash
# Aggressive RAM reclamation and hardened environment setup
# Save as 'secure-env.sh' and run after getting shell access

# Set strict error handling
set -e
trap 'echo "Error on line $LINENO"' ERR

# Colors for visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

# Phase 1: Aggressive RAM Reclamation
reclaim_ram() {
    log "Reclaiming RAM..."
    
    # Kill unnecessary services
    for service in sshd cups bluetooth avahi-daemon systemd-journald; do
        killall -9 $service 2>/dev/null || true
    done
    
    # Stop and disable SSH
    systemctl stop sshd 2>/dev/null || true
    systemctl disable sshd 2>/dev/null || true
    
    # Clear RAM aggressively
    sync
    echo 3 > /proc/sys/vm/drop_caches
    swapoff -a
    
    # Kill known malicious processes (add more as needed)
    for badproc in "crypto" "miner" "kworker" "kthread" ; do
        pkill -f $badproc 2>/dev/null || true
    done
}

# Phase 2: Network Hardening
harden_network() {
    log "Hardening network..."
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
    
    # Configure strict iptables rules
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    # Allow only essential outbound traffic
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Block common attack ports
    for port in 22 23 25 445 3389; do
        iptables -A INPUT -p tcp --dport $port -j DROP
    done
}

# Phase 3: System Hardening
harden_system() {
    log "Hardening system..."
    
    # Protect configuration files
    for conf in /etc/pacman.conf /etc/ssh/sshd_config /etc/resolv.conf; do
        if [ -f "$conf" ]; then
            chattr +i "$conf" 2>/dev/null || true
        fi
    done
    
    # Kernel hardening
    cat > /etc/sysctl.d/99-security.conf << EOF
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=3
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
fs.protected_fifos=2
fs.protected_regular=2
EOF
    sysctl -p /etc/sysctl.d/99-security.conf
}

# Phase 4: Browser Hardening
setup_browser() {
    log "Setting up hardened browser..."
    
    # Create fresh browser profile
    rm -rf ~/.mozilla ~/.config/google-chrome ~/.config/chromium
    
    # Configure Firefox security settings
    mkdir -p ~/.mozilla/firefox/hardened.default
    cat > ~/.mozilla/firefox/hardened.default/user.js << EOF
user_pref("media.peerconnection.enabled", false);  // Disable WebRTC
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("privacy.resistFingerprinting", true);
user_pref("webgl.disabled", true);
user_pref("media.navigator.enabled", false);
user_pref("network.proxy.socks_remote_dns", true);
EOF
}

# Phase 5: Monitoring
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/monitor.sh << 'EOF'
#!/bin/bash
while true; do
    # Check RAM usage
    free -m > /tmp/ram_usage
    
    # Check for new processes
    ps aux > /tmp/process_list
    
    # Check open ports
    netstat -tulpn > /tmp/open_ports
    
    # Alert on high RAM usage
    ram_used=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$ram_used > 80" | bc -l) )); then
        echo "WARNING: High RAM usage detected!"
    fi
    
    sleep 30
done
EOF
    chmod +x /usr/local/bin/monitor.sh
    
    # Start monitoring in background
    /usr/local/bin/monitor.sh &
}

# Main execution
main() {
    log "Starting secure environment setup..."
    
    reclaim_ram
    harden_network
    harden_system
    setup_browser
    setup_monitoring
    
    log "Environment setup complete. Starting X..."
    startx /usr/bin/openbox-session
}

# Run main function
main
