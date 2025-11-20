#!/bin/bash

# Colors for formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to validate IP address
validate_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Function to get IP from user with validation
get_ip() {
    while true; do
        echo -n "Enter target IP address: "
        read TARGET_IP
        if [ -z "$TARGET_IP" ]; then
            echo -e "${RED}Error: IP address cannot be empty${NC}"
            continue
        fi
        
        if validate_ip "$TARGET_IP"; then
            break
        else
            echo -e "${RED}Error: '$TARGET_IP' is not a valid IP address${NC}"
        fi
    done
}

# Function to safely remove rules by IP and pattern
remove_rules_by_ip() {
    local ip=$1
    local pattern=$2
    local chain=${3:-INPUT}
    local removed=0
    local max_iterations=50
    local iteration=0
    
    while [ $iteration -lt $max_iterations ]; do
        local rule_line=$(iptables -L "$chain" -n --line-numbers 2>/dev/null | \
            awk -v ip="$ip" -v pattern="$pattern" '
            /^[0-9]+/ {
                if ($0 ~ ip && $0 ~ pattern) {
                    print $1
                    exit
                }
            }')
        
        if [ -z "$rule_line" ]; then
            break
        fi
        
        if sudo iptables -D "$chain" "$rule_line" 2>/dev/null; then
            ((removed++))
        else
            break
        fi
        ((iteration++))
    done
    
    return $((removed > 0 ? 0 : 1))
}

# Function to check if IP is blacklisted
is_ip_blacklisted() {
    local ip=$1
    iptables-save 2>/dev/null | grep -qE "^-A INPUT.*-s $ip.*-j DROP"
}

# Function to check if IP is rate limited
is_ip_ratelimited() {
    local ip=$1
    iptables-save 2>/dev/null | grep -qE "^-A INPUT.*-s $ip.*--limit"
}

# Function to get all blacklisted IPs
get_blacklisted_ips() {
    iptables-save 2>/dev/null | grep -E "^-A INPUT.*-s [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*-j DROP" | \
        sed -n 's/.*-s \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/p' | sort -u
}

# Function to get all rate-limited IPs
get_ratelimited_ips() {
    iptables-save 2>/dev/null | grep -E "^-A INPUT.*-s [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*--limit" | \
        sed -n 's/.*-s \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/p' | sort -u
}

# Function to display status
display_status() {
    echo "Current Mitigation Status:"
    echo "--------------------------"
    
    # Check SYN Cookies status
    SYN_COOKIE_STATUS=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
    if [ "$SYN_COOKIE_STATUS" -eq 1 ]; then
        echo -e "SYN Cookies: ${GREEN}ENABLED${NC}"
    else
        echo -e "SYN Cookies: ${RED}DISABLED${NC}"
    fi
    
    # Check blacklisted IPs
    BLACKLISTED_IPS=$(get_blacklisted_ips)
    if [ -n "$BLACKLISTED_IPS" ]; then
        local count=$(echo "$BLACKLISTED_IPS" | wc -l)
        echo -e "IP Blacklist: ${GREEN}$count IP(s) blocked${NC}"
    else
        echo -e "IP Blacklist: ${RED}None${NC}"
    fi
    
    # Check rate-limited IPs
    RATELIMITED_IPS=$(get_ratelimited_ips)
    if [ -n "$RATELIMITED_IPS" ]; then
        local count=$(echo "$RATELIMITED_IPS" | wc -l)
        echo -e "Rate Limiting: ${GREEN}$count IP(s) limited${NC}"
    else
        echo -e "Rate Limiting: ${RED}None${NC}"
    fi
    echo
}

# Function to display header
display_header() {
    clear
    echo "================================================"
    echo "    DoS Mitigation Controller"
    echo "================================================"
    echo
}

# IP Blacklist functions
blacklist_toggle() {
    get_ip
    
    if is_ip_blacklisted "$TARGET_IP"; then
        echo "Unblocking IP: $TARGET_IP"
        if remove_rules_by_ip "$TARGET_IP" "DROP"; then
            echo -e "${GREEN}Successfully unblocked $TARGET_IP${NC}"
            save_iptables_rules
        else
            echo -e "${RED}Failed to unblock $TARGET_IP${NC}"
        fi
    else
        echo "Blocking IP: $TARGET_IP"
        sudo iptables -I INPUT 1 -s "$TARGET_IP" -j DROP
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully blocked $TARGET_IP${NC}"
            save_iptables_rules
        else
            echo -e "${RED}Failed to block $TARGET_IP${NC}"
        fi
    fi
    sleep 2
}

# Rate limiting functions
ratelimit_toggle() {
    get_ip
    
    if is_ip_ratelimited "$TARGET_IP"; then
        echo "Disabling rate limiting for IP: $TARGET_IP"
        remove_rules_by_ip "$TARGET_IP" "limit"
        remove_rules_by_ip "$TARGET_IP" "DROP"
        if [ $? -eq 0 ] || [ $? -eq 1 ]; then
            echo -e "${GREEN}Rate limiting disabled for $TARGET_IP${NC}"
            save_iptables_rules
        else
            echo -e "${RED}Failed to disable rate limiting${NC}"
        fi
    else
        echo "Enabling rate limiting for IP: $TARGET_IP (5 packets/sec)"
        sudo iptables -I INPUT 1 -s "$TARGET_IP" -m limit --limit 5/s --limit-burst 10 -j ACCEPT
        sudo iptables -I INPUT 2 -s "$TARGET_IP" -j DROP
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Rate limiting enabled for $TARGET_IP${NC}"
            save_iptables_rules
        else
            echo -e "${RED}Failed to enable rate limiting${NC}"
        fi
    fi
    sleep 2
}

# SYN Cookies functions
syncookies_toggle() {
    SYN_COOKIE_STATUS=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
    
    if [ "$SYN_COOKIE_STATUS" -eq 1 ]; then
        echo "Disabling SYN Cookies protection"
        sudo sysctl -w net.ipv4.tcp_syncookies=0
        # Remove from sysctl.conf if present
        if grep -q "^net.ipv4.tcp_syncookies" /etc/sysctl.conf 2>/dev/null; then
            sudo sed -i '/^net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
        fi
        echo -e "${YELLOW}SYN Cookies protection disabled${NC}"
    else
        echo "Enabling SYN Cookies protection"
        sudo sysctl -w net.ipv4.tcp_syncookies=1
        # Add to sysctl.conf if not already present
        if ! grep -q "^net.ipv4.tcp_syncookies=1" /etc/sysctl.conf 2>/dev/null; then
            # Remove any existing entries first
            sudo sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
            # Add the setting
            echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf > /dev/null
        fi
        echo -e "${GREEN}SYN Cookies protection enabled${NC}"
    fi
    sleep 2
}

# Function to save iptables rules
save_iptables_rules() {
    if command -v netfilter-persistent &> /dev/null; then
        sudo netfilter-persistent save 2>/dev/null
    elif [ -d /etc/iptables ]; then
        sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null 2>&1
    fi
}

# Function to clear all iptables rules
clear_iptables() {
    echo -e "${YELLOW}WARNING: This will clear ALL iptables rules!${NC}"
    echo -n "Are you sure? (yes/no): "
    read confirm
    if [ "$confirm" = "yes" ] || [ "$confirm" = "y" ]; then
        echo "Clearing all IPTables rules..."
        sudo iptables -F
        sudo iptables -X
        save_iptables_rules
        echo -e "${GREEN}All IPTables rules cleared${NC}"
    else
        echo "Operation cancelled."
    fi
    sleep 2
}

# Main menu function
main_menu() {
    while true; do
        display_header
        display_status
        
        echo "Options:"
        echo "1. IP Blacklist (Toggle)"
        echo "2. Rate Limiting (Toggle)"
        echo "3. SYN Cookies (Toggle)"
        echo "4. Clear All IPTables Rules"
        echo "5. Exit"
        echo
        
        echo -n "Select an option (1-5): "
        read choice
        
        case $choice in
            1)
                blacklist_toggle
                ;;
            2)
                ratelimit_toggle
                ;;
            3)
                syncookies_toggle
                ;;
            4)
                clear_iptables
                ;;
            5)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Check if required tools are available
check_dependencies() {
    if ! command -v iptables &> /dev/null; then
        echo -e "${RED}Error: iptables is not installed${NC}"
        exit 1
    fi
}

# Check if running with sudo privileges
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        if ! sudo -n true 2>/dev/null; then
            echo -e "${YELLOW}Warning: Some operations may require sudo privileges${NC}"
            echo "You may be prompted for your password."
            sleep 2
        fi
    fi
}

# Initialize
check_dependencies
check_privileges
main_menu
