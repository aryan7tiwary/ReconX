#!/bin/bash

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script requires superuser privileges. Please run with 'sudo'."
        exit 1
    fi
}

display_names() {
    # Clear the screen
    clear
    
    # Display the script name in large font
    figlet "ReconX"
    echo "@aryan7tiwary"
}


# Target IP or Domain
TARGET=$1

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target-ip-or-domain>"
  exit 1
fi

echo "Starting initial penetration testing on $TARGET"


# Open Port Scan
nmap_open_port() {
    echo "Finding Open Ports..."
    nmap -p- --min-rate 10000 "$TARGET" | tee open_ports.txt
}


service_scan() {
    echo "Do you want to perform a service scan? (yes/no)"
    read -r answer

    if [[ "$answer" == "yes" ]]; then
        echo "Enter port numbers to scan (comma-separated), or type 'all' to scan all open ports:"
        read -r ports

        if [[ "$ports" == "all" ]]; then
            # Read open ports from the file and scan
            ports_to_scan=$(< ./open_ports.txt grep "open" | awk -F'/' '{print $1}' | paste -sd ',')
            echo "Scanning all open ports: $ports_to_scan"
            nmap -sV -sV -p"$ports_to_scan" "$TARGET"
        else
            # Use the user-provided port numbers for the scan
            echo "Scanning specified ports: $ports"
            nmap -sV -p"$ports" "$TARGET"
        fi
    else
        echo "Service scan canceled."
    fi
}


# Exporting domain name
domain_scan() {
    domain_name=$(whatweb "$TARGET" --no-error | sed -n 's|.*http[s]\?://\([a-zA-Z0-9.-]\+\).*|\1|p' | uniq)
    echo "Domain name found: ""$domain_name"""

    echo "Do you want to add domain to the host file? (yes/no)"
    read -r answer
    if [ "$answer" == "yes" ]; then
        sudo echo "$TARGET     $domain_name" | tee -a /etc/hosts
    else
        echo "Not writing host file."
    fi
}

display_names
check_sudo
domain_scan







