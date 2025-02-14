#!/bin/bash

# Title: Network and Service Analysis Script
# Description: This script provides a comprehensive overview of network and service usage on the system.

echo "=== Network and Service Analysis ==="
echo "This script will analyze your system's network and service usage."
echo "Each step will include a verbose explanation of what is being checked."
echo "------------------------------------"

# Function to print a separator
separator() {
    echo "------------------------------------"
}

# 1. Check Listening Ports
echo "1. Checking Listening Ports..."
echo "This shows which ports are open and listening for incoming connections."
echo "Command: sudo ss -tuln"
separator
sudo ss -tuln
separator
echo "Explanation:"
echo "- 'Local Address:Port' shows the IP and port the service is listening on."
echo "- 'State' indicates the state of the socket (e.g., LISTEN)."
echo "- 'Netid' shows the protocol (tcp/udp)."
separator
echo "Press Enter to continue..."
read

# 2. Check Active Connections
echo "2. Checking Active Connections..."
echo "This shows active network connections (both incoming and outgoing)."
echo "Command: sudo ss -tunp"
separator
sudo ss -tunp
separator
echo "Explanation:"
echo "- 'Local Address:Port' shows the local IP and port."
echo "- 'Peer Address:Port' shows the remote IP and port."
echo "- 'Process' shows the process ID and name using the connection."
separator
echo "Press Enter to continue..."
read

# 3. Check Open Files (Including Network Sockets)
echo "3. Checking Open Files and Network Sockets..."
echo "This shows all open files, including network sockets, and the processes using them."
echo "Command: sudo lsof -i"
separator
sudo lsof -i
separator
echo "Explanation:"
echo "- 'COMMAND' shows the process name."
echo "- 'PID' shows the process ID."
echo "- 'NAME' shows the network address and port."
separator
echo "Press Enter to continue..."
read

# 4. Check Firewall Rules
echo "4. Checking Firewall Rules..."
echo "This shows the current iptables firewall rules."
echo "Command: sudo iptables -L -v -n"
separator
sudo iptables -L -v -n
separator
echo "Explanation:"
echo "- 'Chain' shows the firewall chain (e.g., INPUT, OUTPUT)."
echo "- 'pkts' and 'bytes' show the number of packets and bytes matched by the rule."
echo "- 'target' shows the action (e.g., ACCEPT, DROP)."
separator
echo "Press Enter to continue..."
read

# 5. Check IPv6 Status
echo "5. Checking IPv6 Status..."
echo "This checks if IPv6 is enabled or disabled on your system."
echo "Command: cat /proc/sys/net/ipv6/conf/all/disable_ipv6"
separator
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
separator
echo "Explanation:"
echo "- '0': IPv6 is enabled."
echo "- '1': IPv6 is disabled."
separator
echo "Press Enter to continue..."
read

# 6. Check Running Services
echo "6. Checking Running Services..."
echo "This lists all running services (useful to see what's actively using ports)."
echo "Command: sudo systemctl list-units --type=service --state=running"
separator
sudo systemctl list-units --type=service --state=running
separator
echo "Explanation:"
echo "- 'UNIT' shows the service name."
echo "- 'LOAD' shows if the service is loaded."
echo "- 'ACTIVE' shows if the service is active."
separator
echo "Press Enter to continue..."
read

# 7. Check DNS Configuration
echo "7. Checking DNS Configuration..."
echo "This shows which DNS servers your system is using."
echo "Command: cat /etc/resolv.conf"
separator
cat /etc/resolv.conf
separator
echo "Explanation:"
echo "- 'nameserver' shows the DNS server IP addresses."
separator
echo "Press Enter to continue..."
read

# 8. Check UDP Traffic
echo "8. Checking UDP Traffic..."
echo "This shows active UDP connections (if any)."
echo "Command: sudo ss -uap"
separator
sudo ss -uap
separator
echo "Explanation:"
echo "- 'Local Address:Port' shows the local IP and port."
echo "- 'Peer Address:Port' shows the remote IP and port."
echo "- 'Process' shows the process ID and name using the connection."
separator
echo "Press Enter to continue..."
read

# 9. Check HTTP Traffic
echo "9. Checking HTTP Traffic..."
echo "This shows active HTTP connections (useful if you're running a web server)."
echo "Command: sudo netstat -tpn | grep :80"
separator
sudo netstat -tpn | grep :80
separator
echo "Explanation:"
echo "- 'Local Address' shows the local IP and port."
echo "- 'Foreign Address' shows the remote IP and port."
echo "- 'PID/Program name' shows the process ID and name."
separator
echo "Press Enter to continue..."
read

# 10. Check Kernel Routing Table
echo "10. Checking Kernel Routing Table..."
echo "This shows the current routing table (useful to see how traffic is being routed)."
echo "Command: ip route show"
separator
ip route show
separator
echo "Explanation:"
echo "- 'default via' shows the default gateway."
echo "- Other entries show specific routes for networks."
separator
echo "Press Enter to continue..."
read

# 11. Check Network Logs
echo "11. Checking Network Logs..."
echo "This shows recent network-related logs (useful for troubleshooting)."
echo "Command: sudo journalctl -u NetworkManager"
separator
sudo journalctl -u NetworkManager
separator
echo "Explanation:"
echo "- Logs show network-related events and errors."
separator
echo "Press Enter to continue..."
read

# 12. Check for Open UDP Ports
echo "12. Checking for Open UDP Ports..."
echo "This scans for open UDP ports (if any)."
echo "Command: sudo nmap -sU -p- localhost"
separator
sudo nmap -sU -p- localhost
separator
echo "Explanation:"
echo "- 'PORT' shows the UDP port number."
echo "- 'STATE' shows if the port is open or closed."
echo "- 'SERVICE' shows the service associated with the port."
separator
echo "Script completed. Review the output above for details."
