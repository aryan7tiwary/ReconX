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

# Check if user provided IP or domain name
function check_if_domain()  {
    if [[ "$TARGET" =~ ^[a-z] ]]; then
    return 1
    else
    return 0
    fi
}

# Open Port Scan
nmap_open_port() {
    echo "Finding Open Ports..."
    nmap -p- --min-rate 10000 "$TARGET" | tee open_ports.txt || {
        echo "Nmap scan failed. Please ensure that Nmap is installed and try again."
        exit 1
    }
}

service_scan() {
    echo "Do you want to perform a service scan? (yes/no)"
    read -r answer

    if [[ "$answer" == "yes" ]]; then
        echo "Enter port numbers to scan (comma-separated), or type 'all' to scan all open ports:"
        read -r ports

        if [[ "$ports" == "all" ]]; then
            # Read open ports from the file and scan
            ports_to_scan=$(grep "open" open_ports.txt | awk -F'/' '{print $1}' | paste -sd ',')
            echo "Scanning all open ports: $ports_to_scan"
            nmap -sV -p"$ports_to_scan" "$TARGET" || {
                echo "Nmap service scan failed."
                exit 1
            }
        else
            # Use the user-provided port numbers for the scan
            echo "Scanning specified ports: $ports"
            nmap -sV -p"$ports" "$TARGET" || {
                echo "Nmap service scan failed."
                exit 1
            }
        fi
    else
        echo "Service scan canceled."
    fi
}

# Exporting domain name
function domain_scan() {
    echo "Finding domain for $TARGET..."
    domain_name=$(whatweb "$TARGET" --no-error | sed -n 's|.*http[s]\?://\([a-zA-Z0-9.-]\+\).*|\1|p' | uniq)
    
    if [ -z "$domain_name" ]; then
        echo "No domain name found."
        return 0
    else
        echo "Domain name found: $domain_name"
        return 1
    fi
}

update_host_file() {
    echo "Do you want to add the domain to the hosts file? (yes/no)"
    read -r answer
    if [ "$answer" == "yes" ]; then
        sudo bash -c "echo '$TARGET     $domain_name' >> /etc/hosts"
        echo "Domain added to /etc/hosts."
    else
        echo "Not writing to the hosts file."
    fi
}

# Scanning for sub-domain
scan_subdomain() {
    echo "Do you want to perform subdomain scan? (yes/no)"
    read -r answer

    if [[ "$answer" == "yes" ]]; then
        echo "Running sublist3r..."
        sublist3r -n -d mitblrfest.org | grep -Eo '([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}' | tee ./subdomain.txt || {
            echo "sublist3r not found!"
        }
        echo "Fuzzing subdomains..."
        wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u "$domain_name" -H "Host: FUZZ.$domain_name" -f ./.wfuzz_subdomains.txt --sc 200,301 || {
            echo "wfuzz not found!"
        }
        < ./.wfuzz_subdomains.txt cut -d '"' -f 2 | grep -Ev '[0-9]|[ ]|=' | sed '/^$/d' | sed "s/.*/&.$domain_name/" | tee -a ./subdomain.txt
        < subdomain.txt uniq | tee subdomain.txt

    else
        echo "Service scan canceled."
    fi
}

display_names
check_sudo
nmap_open_port
service_scan

if(check_if_domain eq 0); then
    domain_scan
fi

if(scan_subdomain eq 1); then
    update_host_file
fi

if(check_if_domain eq 1); then
    scan_subdomain
else
    echo ""
fi