import subprocess
import os
import sys
import shutil
import argparse
import re

def check_sudo():
    if os.geteuid() != 0:
        print("This script requires superuser privileges. Please run with 'sudo'.")
        sys.exit(1)

def display_names():
    os.system('clear')
    print("ReconX")
    print("@aryan7tiwary")

def check_dependencies():
    dependencies = ['nmap', 'whatweb', 'sublist3r', 'wfuzz']
    for cmd in dependencies:
        if shutil.which(cmd) is None:
            print(f"{cmd} not found! Please install it.")
            sys.exit(1)

def is_IP(target):
    return target.replace('.', '').isdigit()  # Check if target is an IP

def nmap_open_port(target, logfile):
    answer = input("Do you want to perform a port scan? (yes/no): ").strip().lower()
    if answer == "yes":
        print(f"Finding Open Ports on {target}...")

        # Open 'open_ports.txt' in write mode to overwrite the content
        try:
            with open('open_ports.txt', 'w') as open_ports_file:  # Overwrite the file each time
                process = subprocess.Popen(
                    ['nmap', '-p-', '--min-rate', '10000', target],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )

                # Read output line by line in real-time
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.strip())  # Print the output as it arrives
                        open_ports_file.write(output)  # Write output to file
                        
                _, errors = process.communicate()  # Read any remaining output or errors
                if errors:
                    print(f"Error during Nmap scan: {errors}")
        except Exception as e:
            print(f"Error running Nmap: {e}")
            sys.exit(1)
    else:
        print("Skipping Port Scan")


def service_scan(target, logfile):
    answer = input("Do you want to perform a service scan? (yes/no): ").strip().lower()
    if answer == "yes":
        ports = input("Enter port numbers to scan (comma-separated), or type 'all' to scan all open ports: ").strip()
        if ports == "all":
            ports_to_scan = ','.join([line.split('/')[0] for line in open('open_ports.txt') if 'open' in line])
        else:
            ports_to_scan = ports
        print(f"Scanning specified ports: {ports_to_scan}")
        try:
            # Run nmap with -sV to scan services and overwrite 'service.txt'
            with open('service.txt', 'w') as service_file:  # Overwrite the file each time
                subprocess.run(
                    ['nmap', '-sV', '-p', ports_to_scan, target],
                    stdout=service_file, stderr=subprocess.STDOUT  # Capture both stdout and stderr in the file
                )
            print(f"Service scan results written to service.txt")
        except Exception as e:
            print(f"Error running service scan: {e}")
            sys.exit(1)
    else:
        print("Service scan canceled.")


def update_hosts_file(target, domains):
    entry = f"{target}\t{domains}\n"
    existing_domains = get_existing_domains()
    domain_list = domains.split()
    new_domains = [domain for domain in domain_list if domain not in existing_domains]
    if new_domains:
        new_entry = f"{target}\t{' '.join(new_domains)}\n"
        try:
            with open("/etc/hosts", "a") as hosts_file:
                hosts_file.write(new_entry)
            print(f"Successfully added: {new_entry.strip()} to /etc/hosts")
        except PermissionError:
            print("Permission denied. Please run the script with sudo privileges.")
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("No new domains to add. All domains already exist in /etc/hosts.")

def get_existing_domains():
    existing_domains = set()
    try:
        with open("/etc/hosts", "r") as hosts_file:
            for line in hosts_file:
                if not line.startswith('#') and line.strip():
                    parts = line.split()
                    if len(parts) > 1:
                        existing_domains.update(parts[1:])
    except Exception as e:
        print(f"Error reading /etc/hosts: {e}")
    return existing_domains

def domain_scan(target, logfile):
    print("Scanning for domain...")
    completed_process = subprocess.run(
        ['whatweb', target, '--no-error', '--color=NEVER'], 
        capture_output=True, text=True
    )
    stdout_text = completed_process.stdout
    domain_pattern = re.compile(r'http[s]?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    domains = domain_pattern.findall(stdout_text)
    if domains:
        domain_string = ' '.join(set(domains))  # Ensure unique domains
        update_hosts_file(target, domain_string)
        return list(set(domains))  # Return the list of unique domains
    else:
        print("No domains found to update in /etc/hosts")
        return []

import subprocess

def scan_subdomain(domains, logfile):
    answer = input("Do you want to perform a subdomain scan? (yes/no): ").strip().lower()
    if answer == "yes":
        all_subdomains = []  # List to store all found subdomains
        for domain in domains:
            print(f"Running Sublist3r for {domain}...")
            try:
                # Run Sublist3r and write results to subdomain.txt
                subprocess.run(['sublist3r', '-n', '-d', domain, '-o', 'subdomain.txt'], check=True)
                
                print(f"Subdomain scan for {domain} complete.")
                
                # Read subdomains found by Sublist3r
                with open('subdomain.txt', 'r') as subdomain_file:
                    found_subdomains = subdomain_file.readlines()
                    all_subdomains.extend([subdomain.strip() for subdomain in found_subdomains if subdomain.strip()])
            
            except Exception as e:
                print(f"Error during subdomain scan for {domain}: {e}")
        
        # Ask for consent to run wfuzz on the original domains
        consent = input("Do you want to fuzz the original domains for additional subdomains with wfuzz? (yes/no): ").strip().lower()
        if consent == "yes":
            for domain in domains:
                print(f"Fuzzing subdomains for {domain} with wfuzz...")
                try:
                    subprocess.run(
                        ['wfuzz', '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
                         '-u', f"http://{domain}", '-H', f"Host: FUZZ.{domain}",
                         '-f', '.wfuzz_subdomains.txt', '--sc', '200,301'], 
                        stdout=subprocess.DEVNULL
                    )
                    # Process wfuzz output and write to file
                    with open('.wfuzz_subdomains.txt', 'r') as wfuzz_output:
                        fuzzed_subdomains = [line.split('"')[1] + f".{domain}" for line in wfuzz_output if '"' in line]
                    
                    with open('subdomain.txt', 'a+') as subdomain_file:
                        subdomain_file.seek(0)
                        existing_subdomains = set(subdomain_file.read().splitlines())
                        new_subdomains = set(fuzzed_subdomains) - existing_subdomains
                        if new_subdomains:
                            subdomain_file.write('\n'.join(new_subdomains) + '\n')

                    print(f"Fuzzing for {domain} complete.")
                except Exception as e:
                    print(f"Error during fuzzing for {domain}: {e}")
        else:
            print("Skipping wfuzz fuzzing.")
    else:
        print("Subdomain scan canceled.")



def main():
    parser = argparse.ArgumentParser(description="ReconX - Initial Penetration Testing Automation")
    parser.add_argument("target", help="Target IP or domain")
    args = parser.parse_args()
    target = args.target
    logfile = "reconx_log.txt"
    
    check_sudo()
    check_dependencies()
    display_names()

    print(f"Starting initial penetration testing on {target}")
    
    nmap_open_port(target, logfile)
    service_scan(target, logfile)

    if is_IP(target):
        found_domains = domain_scan(target, logfile)
        if found_domains:
            scan_subdomain(found_domains, logfile)
    else:
        print("Skipping domain scan as target is not an IP.")
        scan_subdomain([target], logfile)

if __name__ == "__main__":
    main()