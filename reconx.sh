#!/bin/bash

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script requires superuser privileges. Please run with 'sudo'."
        exit 1
    fi
}

display_names() {
    clear
    figlet "ReconX"
    echo "@aryan7tiwary"
}

TARGET=$1
LOGFILE="reconx_log.txt"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip-or-domain>"
    exit 1
fi

echo "Starting initial penetration testing on $TARGET" | tee -a "$LOGFILE"

check_dependencies() {
    for cmd in nmap whatweb sublist3r wfuzz; do
        if ! which "$cmd" > /dev/null; then
            echo "$cmd not found! Please install it."
            exit 1
        fi
    done
}

is_domain() {
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0  # It's an IP
    else
        return 1  # It's a domain
    fi
}

nmap_open_port() {
    echo "Do you want to perform a service scan? (yes/no)"
    read -r answer
    if [[ "$answer" == "yes" ]]; then
        echo "Finding Open Ports..." | tee -a "$LOGFILE"
        nmap -p- --min-rate 10000 "$TARGET" | tee open_ports.txt || {
            echo "Nmap scan failed." | tee -a "$LOGFILE"
            exit 1
        }
    else echo "Skipping Port Scan"
    fi
}

service_scan() {
    echo "Do you want to perform a service scan? (yes/no)"
    read -r answer
    if [[ "$answer" == "yes" ]]; then
        echo "Enter port numbers to scan (comma-separated), or type 'all' to scan all open ports:"
        read -r ports
        if [[ "$ports" == "all" ]]; then
            ports_to_scan=$(grep "open" open_ports.txt | awk -F'/' '{print $1}' | paste -sd ',')
            echo "Scanning all open ports: $ports_to_scan" | tee -a "$LOGFILE"
            nmap -sV -p"$ports_to_scan" "$TARGET" || {
                echo "Nmap service scan failed." | tee -a "$LOGFILE"
                exit 1
            }
        else
            echo "Scanning specified ports: $ports" | tee -a "$LOGFILE"
            nmap -sV -p"$ports" "$TARGET" || {
                echo "Nmap service scan failed." | tee -a "$LOGFILE"
                exit 1
            }
        fi
    else
        echo "Service scan canceled."
    fi
}

domain_scan() {
    echo "Finding domain for $TARGET..." | tee -a "$LOGFILE"
    domain_name=$(whatweb "$TARGET" --no-error | sed -n 's|.*http[s]\?://\([a-zA-Z0-9.-]\+\).*|\1|p' | uniq)
    
    if [ -z "$domain_name" ]; then
        echo "No domain name found." | tee -a "$LOGFILE"
        return 1  # Indicate failure (no domain found)
    else
        echo "Domain name found: $domain_name" | tee -a "$LOGFILE"
        return 0  # Indicate success (domain found)
    fi
}


update_host_file() {
    echo "Do you want to add the domain to the hosts file? (yes/no)"
    read -r answer
    if [ "$answer" == "yes" ]; then
        sudo bash -c "echo '$TARGET     $domain_name' >> /etc/hosts"
        echo "Domain added to /etc/hosts." | tee -a "$LOGFILE"
    else
        echo "Not writing to the hosts file." | tee -a "$LOGFILE"
    fi
}

scan_subdomain() {
    echo "Do you want to perform subdomain scan? (yes/no)"
    read -r answer
    if [[ "$answer" == "yes" ]]; then
        echo "Running sublist3r..." | tee -a "$LOGFILE"
        sublist3r -n -d "$domain_name" | grep -Eo '([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}' > ./subdomain.txt || {
            echo "sublist3r not found!" | tee -a "$LOGFILE"
        }
        echo "Fuzzing subdomains..." | tee -a "$LOGFILE"
        wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u "$domain_name" -H "Host: FUZZ.$domain_name" -f ./.wfuzz_subdomains.txt --sc 200,301 > /dev/null || {
            echo "wfuzz not found!" | tee -a "$LOGFILE"
        }
        < ./.wfuzz_subdomains.txt cut -d '"' -f 2 | grep -Ev '[0-9]|[ ]|=' | sed '/^$/d' | sed "s/.*/&.$domain_name/" >> ./subdomain.txt
        uniq subdomain.txt > tmpfile.txt && mv tmpfile.txt subdomain.txt
    else
        echo "Subdomain scan canceled."
    fi
}

check_sudo
check_dependencies
display_names

nmap_open_port
service_scan

if is_domain; then
    if domain_scan; then  # Only run if domain_scan is successful
        update_host_file
        scan_subdomain
    else
        echo "Domain scan failed. Skipping subdomain scan."
    fi
fi

# Clean up
rm -f ./.wfuzz_subdomains.txt