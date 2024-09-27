# ReconX Automation Script

## Overview

The **ReconX** script is a shell-based automation tool designed for initial penetration testing. It streamlines various reconnaissance tasks, including open port scanning, service identification, and domain name extraction. This script is intended for use by cybersecurity professionals and ethical hackers.

## Features

- **Open Port Scanning**: Identify open ports on a target IP or domain.
- **Service Version Scanning**: Optionally perform a service scan on the identified open ports.
- **Domain Name Extraction**: Extract the domain name from the target and optionally add it to the hosts file.

## Prerequisites

Before using this script, ensure you have the following tools installed:

- **nmap**: A powerful network scanning tool.
- **whatweb**: A web application fingerprinting tool.
- **figlet**: For displaying large text in the terminal.

You can install these tools using the following commands on Debian-based systems:

```bash
sudo apt update 
sudo apt install nmap whatweb figlet
```

## Usage

1. **Clone the repository** or download the script file.
    
2. **Navigate to the directory** where the script is located.
    
3. **Make the script executable**:
	```bash
	chmod +x reconx.sh
	```
    
4. **Run the script with superuser privileges**:
	```bash
	sudo ./reconx.sh <target-ip-or-domain>
	```
    
    Replace `<target-ip-or-domain>` with the target you want to analyze.
    

## Example

```bash
sudo ./reconx.sh 192.168.1.1
```

## Script Functions

- `check_sudo()`: Checks if the script is run with superuser privileges.
- `display_names()`: Displays the script name and author information.
- `nmap_open_port()`: Scans the target for open ports and saves the results to `open_ports.txt`.
- `service_scan()`: Prompts the user to perform a service scan on open ports.
- `domain_scan()`: Extracts the domain name from the target and offers to add it to the hosts file.

## Notes

- **Permission**: The script requires superuser privileges to perform certain actions, such as modifying the hosts file.
- **Usage Caution**: Ensure you have permission to scan the target IP or domain to avoid legal issues.

## License

This script is released under the MIT License. Feel free to modify and distribute it as you see fit.

## Author

**Aryan Tiwary**  
[@aryan7tiwary](https://twitter.com/aryan7tiwary)
