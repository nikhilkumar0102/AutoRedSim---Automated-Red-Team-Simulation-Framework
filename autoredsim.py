import subprocess
import os
from datetime import datetime
import time
import sys
import threading

# For colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Beautiful Banner
BANNER = f"""
{Colors.OKGREEN}{Colors.BOLD}
    ___            _          ___         ___ _          
   / _ \\          | |         / _ \\       /   | |          
  / /_\\ \\_   _ | |_ ___  / /_\\ \\_ __  / /| | |_ ___ _ __ 
 |  _  | | | | | __/ _ \\|  _  | '_ \\ / /_| | __/ _ \\ '__|
 | | | | |_| | | || (_) | | | | | | \\____ | ||  __/ |   
 \\_| |_/\\__,_| \\__\\___/\\_| |_/| |_(_\\___/ \\__\\___|_|   
                                                        
AutoRedSim - Automated Red Team Simulation Framework
Version 0.1
{Colors.END}
"""

def check_python3():
    """Verify if python3 is installed."""
    try:
        subprocess.run(["which", "python3"], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"{Colors.FAIL}[!] Error: 'python3' is not installed or not in your PATH.{Colors.END}")
        print(f"{Colors.FAIL}[!] Install Python 3 using your package manager (e.g., 'sudo apt install python3' on Debian/Ubuntu).{Colors.END}")
        return False

def confirm_authorization():
    """Prompt user to confirm they have permission to scan."""
    response = input(f"{Colors.WARNING}Do you have explicit authorization to conduct this operation? (yes/no): {Colors.END}").lower()
    if response != "yes":
        print(f"{Colors.FAIL}[!] Mission aborted. Authorization not confirmed.{Colors.END}")
        sys.exit(1)

def perform_shodan_recon():
    """Launch Shodan Reconnaissance module."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the Shodan Reconnaissance module...{Colors.END}")
        shodan_script_path = os.path.join("modules", "shodan_recon.py")
        if not os.path.exists(shodan_script_path):
            print(f"{Colors.FAIL}[!] Error: 'shodan_recon.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", shodan_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] Shodan Reconnaissance module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The Shodan module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_network_discovery():
    """Launch Network Discovery module."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the Network Discovery module...{Colors.END}")
        subprocess_script_path = os.path.join("modules", "network_recon.py")
        if not os.path.exists(subprocess_script_path):
            print(f"{Colors.FAIL}[!] Error: 'network_recon.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", subprocess_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] Network Discovery module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The Network Discovery module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_subdomain_enumeration():
    """Launch Subdomain Enumeration module."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the Subdomain Enumeration module...{Colors.END}")
        subprocess_script_path = os.path.join("modules", "subdomain_enum.py")
        if not os.path.exists(subprocess_script_path):
            print(f"{Colors.FAIL}[!] Error: 'subdomain_enum.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", subprocess_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] Subdomain Enumeration module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The Subdomain Enumeration module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_dns_interrogation():
    """Launch DNS Interrogation module."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the DNS Interrogation module...{Colors.END}")
        subprocess_script_path = os.path.join("modules", "dns_interrogation.py")
        if not os.path.exists(subprocess_script_path):
            print(f"{Colors.FAIL}[!] Error: 'dns_interrogation.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", subprocess_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] DNS Interrogation module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The DNS Interrogation module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_web_directory_brute():
    """Launch Web Directory Brute-Forcing module."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the Web Directory Brute-Forcing module...{Colors.END}")
        subprocess_script_path = os.path.join("modules", "web_brute.py")
        if not os.path.exists(subprocess_script_path):
            print(f"{Colors.FAIL}[!] Error: 'web_brute.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", subprocess_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] Web Directory Brute-Forcing module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The Web Directory Brute-Forcing module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_smb_enumeration():
    """Launch SMB Enumeration module."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the SMB Enumeration module...{Colors.END}")
        subprocess_script_path = os.path.join("modules", "smbenum.py")
        if not os.path.exists(subprocess_script_path):
            print(f"{Colors.FAIL}[!] Error: 'smbenum.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", subprocess_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] SMB Enumeration module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The SMB Enumeration module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_vuln_scan():
    """Launch Vulnerability Assessment module (web_vuln.py)."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the Vulnerability Assessment module...{Colors.END}")
        vuln_script_path = os.path.join("modules", "web_vuln.py")
        if not os.path.exists(vuln_script_path):
            print(f"{Colors.FAIL}[!] Error: 'web_vuln.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", vuln_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] Vulnerability Assessment module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The Vulnerability Assessment module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_brute_scan():
    """Launch Brute-Forcing module (brute.py)."""
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the Brute-Forcing module...{Colors.END}")
        subprocess_script_path = os.path.join("modules", "brute.py")
        if not os.path.exists(subprocess_script_path):
            print(f"{Colors.FAIL}[!] Error: 'brute.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", subprocess_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] Brute-Forcing module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The Brute-Forcing module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")

def perform_exploit_scan():
    """Launch Exploit-Scan """
    try:
        print(f"\n{Colors.OKGREEN}[*] Launching the Exploit module...{Colors.END}")
        subprocess_script_path = os.path.join("modules", "exploit_search.py")
        if not os.path.exists(subprocess_script_path):
            print(f"{Colors.FAIL}[!] Error: 'expolit.py' not found in 'modules' directory.{Colors.END}")
            return
        project_directory = os.getcwd()
        subprocess.run(["python3", subprocess_script_path], check=True, cwd=project_directory)
        print(f"\n{Colors.OKGREEN}[*] Exploit Search module finished. Returning to main menu.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] The Exploit search module exited with an error: {e}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred: {e}{Colors.END}")


def display_main_menu():
    print(f"\n{Colors.HEADER}--- AutoRedSim Main Menu ---{Colors.END}")
    print("1. Reconnaissance")
    print("2. Vulnerability Assessment")
    print("3. Exploitation")
    print("4. Post-Exploitation")
    print("5. Reporting")
    print("6. Exit")
    return input("Select module: ")

def display_recon_menu():
    print(f"\n{Colors.HEADER}--- Reconnaissance Sub-Menu ---{Colors.END}")
    print("1. Passive Scanning")
    print("2. Active Scanning")
    print("3. Back to Main Menu")
    return input("Select scanning type: ")

def display_passive_menu():
    print(f"\n{Colors.HEADER}--- Passive Scanning Options ---{Colors.END}")
    print("1. Shodan Reconnaissance")
    print("2. Subdomain Enumeration")
    print("3. DNS Interrogation")
    print("4. Back to Recon Menu")
    return input("Select option: ")

def display_active_menu():
    print(f"\n{Colors.HEADER}--- Active Scanning Options ---{Colors.END}")
    print("1. Network Discovery")
    print("2. Web Directory Brute-Forcing")
    print("3. SMB Enumeration")
    print("4. Back to Recon Menu")
    return input("Select option: ")

def display_vuln_menu():
    print(f"\n{Colors.HEADER}--- Vulnerability Assessment Sub-Menu ---{Colors.END}")
    print("1. Web Vulnerability Scanning")
    print("2. Credential Weackness Scanning")
    print("3. Explot Search ")
    print("4. Back to Main Menu")
    return input("Select option: ")

def main():
    if not check_python3():
        sys.exit(1)
    print(BANNER)
    confirm_authorization()
    while True:
        choice = display_main_menu()
        if choice == '1':
            while True:
                recon_choice = display_recon_menu()
                if recon_choice == '1':
                    while True:
                        passive_choice = display_passive_menu()
                        if passive_choice == '1':
                            perform_shodan_recon()
                        elif passive_choice == '2':
                            perform_subdomain_enumeration()
                        elif passive_choice == '3':
                            perform_dns_interrogation()
                        elif passive_choice == '4':
                            break
                        else:
                            print(f"{Colors.FAIL}[!] Invalid option.{Colors.END}")
                elif recon_choice == '2':
                    while True:
                        active_choice = display_active_menu()
                        if active_choice == '1':
                            perform_network_discovery()
                        elif active_choice == '2':
                            perform_web_directory_brute()
                        elif active_choice == '3':
                            perform_smb_enumeration()
                        elif active_choice == '4':
                            break
                        else:
                            print(f"{Colors.FAIL}[!] Invalid option.{Colors.END}")
                elif recon_choice == '3':
                    break
                else:
                    print(f"{Colors.FAIL}[!] Invalid scanning type.{Colors.END}")
        elif choice == '2':
            while True:
                vuln_choice = display_vuln_menu()
                if vuln_choice == '1':
                    perform_vuln_scan()
                elif vuln_choice == '2':  # Fixed: Changed brute_choice to vuln_choice
                    perform_brute_scan()
                elif vuln_choice == '3':
                    perform_exploit_scan()
                elif vuln_choice == '4':
                    break
                else:
                    print(f"{Colors.FAIL}[!] Invalid option.{Colors.END}")
        elif choice == '3':
            print(f"\n{Colors.WARNING}Exploitation module coming soon...{Colors.END}")
        elif choice == '4':
            print(f"\n{Colors.WARNING}Post-Exploitation module coming soon...{Colors.END}")
        elif choice == '5':
            print(f"\n{Colors.WARNING}Reporting module coming soon...{Colors.END}")
        elif choice == '6':
            print(f"{Colors.OKBLUE}[*] Exiting framework. Stay stealthy.{Colors.END}")
            break
        else:
            print(f"{Colors.FAIL}[!] Invalid module selected.{Colors.END}")

if __name__ == "__main__":
    main()
