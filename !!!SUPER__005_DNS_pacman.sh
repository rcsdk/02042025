#!/bin/bash

#---------------------------
# Test DNS Servers for Speed and Lock Down the Fastest
echo "Testing DNS servers for speed..."

# List of DNS servers to test
dns_servers=(
    "1.1.1.1"       # Cloudflare
    "9.9.9.9"       # Quad9
    "8.8.8.8"       # Google
    "208.67.222.222" # OpenDNS
    "84.200.69.80"  # DNS.WATCH
    "94.140.14.14"  # AdGuard
)

# Temporary file to store results
dns_results="/tmp/dns_speed_results.txt"
> "$dns_results"

# Test each DNS server
for dns in "${dns_servers[@]}"; do
    echo "Testing $dns..."
    avg_time=$(dig +time=2 +tries=1 @$dns google.com | grep "Query time:" | awk '{print $4}')
    if [[ -n "$avg_time" ]]; then
        echo "$dns $avg_time ms" >> "$dns_results"
    else
        echo "$dns failed" >> "$dns_results"
    fi
done

# Sort results by speed (fastest first)
sort -n -k2 "$dns_results" -o "$dns_results"

# Display results
echo "DNS Servers sorted by speed:"
cat "$dns_results"

# Lock down the fastest DNS server
fastest_dns=$(awk 'NR==1 {print $1}' "$dns_results")
if [[ -n "$fastest_dns" ]]; then
    echo "Locking down the fastest DNS server: $fastest_dns"
    echo "nameserver $fastest_dns" | sudo tee /etc/resolv.conf
else
    echo "Error: No valid DNS server found."
fi

#---------------------------
# Update /etc/pacman.conf
echo "Updating /etc/pacman.conf..."

cat << EOF | sudo tee /etc/pacman.conf
#
# /etc/pacman.conf
#
# See the pacman.conf(5) manpage for option and repository directives
#

#
# GENERAL OPTIONS
#

[options]
RootDir     = /
DBPath      = /var/lib/pacman/
CacheDir    = /var/cache/pacman/pkg/
HookDir     = /etc/pacman.d/hooks/
GPGDir      = /etc/pacman.d/gnupg/
LogFile     = /var/log/pacman.log
HoldPkg     = pacman glibc man-db bash syslog-ng systemd
IgnorePkg   =
IgnoreGroup =
NoUpgrade   =
NoExtract   =
UseSyslog
Color
ILoveCandy

Architecture = x86_64

# Require package signatures
SigLevel = Required DatabaseOptional

#
# REPOSITORIES
#

[core]
Include     = /etc/pacman.d/mirrorlist

[extra]
Include     = /etc/pacman.d/mirrorlist

[community]
Include     = /etc/pacman.d/mirrorlist

[multilib]
Include     = /etc/pacman.d/mirrorlist

#[testing]
#Include     = /etc/pacman.d/mirrorlist

#[community-testing]
#Include     = /etc/pacman.d/mirrorlist

#[multilib-testing]
#Include     = /etc/pacman.d/mirrorlist
EOF

echo "/etc/pacman.conf has been updated."

#---------------------------
# Secure /etc/pacman.conf
echo "Locking down /etc/pacman.conf..."

# Backup the original file
sudo cp /etc/pacman.conf /etc/pacman.conf.bak

# Apply secure permissions
sudo chmod 644 /etc/pacman.conf
sudo chown root:root /etc/pacman.conf

echo "/etc/pacman.conf has been locked down."
