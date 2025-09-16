import subprocess
import os
import time
import sys
import threading
import re
import json
import csv
from tabulate import tabulate
import ipaddress

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

# Simple banner
BANNER = f"""
{Colors.OKGREEN}{Colors.BOLD}=======================================
           Brute-Force Check
=======================================
{Colors.WARNING}Use ethically and only on authorized systems!{Colors.END}
"""

# Service definitions for brute-force and access commands
SERVICES = {
    "21": {"port": 21, "name": "ftp", "description": "FTP (File Transfer Protocol)", "access_cmd": lambda ip, login, password: ["ftp", ip]},
    "22": {"port": 22, "name": "ssh", "description": "SSH (Secure Shell)", "access_cmd": lambda ip, login, password: ["ssh", f"{login}@{ip}"]},
    "23": {"port": 23, "name": "telnet", "description": "Telnet", "access_cmd": lambda ip, login, password: ["telnet", ip]},
    "1433": {"port": 1433, "name": "mssql", "description": "MSSQL (Microsoft SQL Server)", "access_cmd": lambda ip, login, password: ["mssql-cli", "-S", ip, "-U", login, "-P", password]},
    "3306": {"port": 3306, "name": "mysql", "description": "MySQL", "access_cmd": lambda ip, login, password: ["mysql", "-h", ip, "-u", login, f"-p{password}"]},
    "3389": {"port": 3389, "name": "rdp", "description": "RDP (Remote Desktop Protocol)", "access_cmd": lambda ip, login, password: ["rdesktop", ip, "-u", login, "-p", password]},
    "5900": {"port": 5900, "name": "vnc", "description": "VNC (Virtual Network Computing)", "access_cmd": lambda ip, login, password: ["vncviewer", ip]},
    "5432": {"port": 5432, "name": "postgresql", "description": "PostgreSQL", "access_cmd": lambda ip, login, password: ["psql", "-h", ip, "-U", login, f"-W{password}"]}
}

def check_tools(tool: str) -> bool:
    """Verify if a tool is installed."""
    try:
        subprocess.run(["which", tool], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"{Colors.FAIL}[!] Error: '{tool}' is not installed or not in your PATH.{Colors.END}")
        if tool == "nmap":
            print(f"{Colors.FAIL}[!] On Debian/Ubuntu, install it with: sudo apt install nmap{Colors.END}")
        elif tool == "hydra":
            print(f"{Colors.FAIL}[!] On Debian/Ubuntu, install it with: sudo apt install hydra{Colors.END}")
        elif tool in ["ftp", "ssh", "telnet", "mysql", "mssql-cli", "rdesktop", "vncviewer", "psql"]:
            print(f"{Colors.FAIL}[!] On Debian/Ubuntu, install it with: sudo apt install {tool}{Colors.END}")
        return False

def validate_ip(target_ip: str) -> bool:
    """Validate if the input is a valid IP address."""
    try:
        ipaddress.ip_address(target_ip)
        return True
    except ValueError:
        print(f"{Colors.FAIL}[!] Invalid IP address: {target_ip}{Colors.END}")
        return False

def require_positive_authorization(target_ip: str, operation: str) -> bool:
    """Prompt user to confirm authorization with audit trail."""
    print(f"\n{Colors.WARNING}Target IP: {target_ip} | Operation: {operation}{Colors.END}")
    response = input(f"{Colors.WARNING}Do you have explicit written authorization to perform this operation? (yes/no): {Colors.END}").lower()
    if response != "yes":
        print(f"{Colors.FAIL}[!] Authorization not confirmed. Exiting.{Colors.END}")
        return False

    log_dir = os.path.expanduser("~/.brute_force_logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "audit_log.txt"), "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | Target IP: {target_ip} | Operation: {operation} | User: {os.getlogin()} | Status: Authorized\n")
    return True

def log_access_attempt(target_ip: str, service: dict, login: str, password: str, status: str) -> None:
    """Log access attempt to audit log."""
    log_dir = os.path.expanduser("~/.brute_force_logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "audit_log.txt"), "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | Target IP: {target_ip} | Service: {service['description']} (Port {service['port']}) | Login: {login} | Password: {password} | Operation: Access Attempt | Status: {status}\n")

def run_command(cmd: list) -> str:
    """Runs a command and returns its output, handling errors."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=300
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"{Colors.FAIL}Command failed: {e.stderr or e.stdout}{Colors.END}"
    except FileNotFoundError:
        return f"{Colors.FAIL}Error: '{cmd[0]}' not found. Is it installed and in your PATH?{Colors.END}"
    except subprocess.TimeoutExpired:
        return f"{Colors.FAIL}Error: Command timed out after 5 minutes.{Colors.END}"

def scan_open_ports(target_ip: str) -> list:
    """Scan for open ports using nmap and return brute-forceable ports."""
    print(f"{Colors.OKBLUE}[*] Scanning for open ports on {target_ip}...{Colors.END}")
    output = run_command(["nmap", "-p1-65535", "--open", target_ip])
    if "failed" in output.lower() or "Error" in output:
        print(output)
        return []

    port_regex = re.compile(r"(\d+)/tcp\s+open\s+\w+")
    open_ports = [int(match.group(1)) for match in port_regex.finditer(output)]
    brute_forceable_ports = [port for port in open_ports if str(port) in SERVICES]
    
    if not brute_forceable_ports:
        print(f"{Colors.OKGREEN}[*] No brute-forceable ports found on {target_ip}.{Colors.END}")
    else:
        print(f"{Colors.HEADER}[*] Brute-forceable ports found:{Colors.END}")
        for i, port in enumerate(brute_forceable_ports, 1):
            print(f"{Colors.HEADER}{i}. {SERVICES[str(port)]['description']} ({port}){Colors.END}")
    
    return brute_forceable_ports

def select_ports(brute_forceable_ports: list) -> list:
    """Prompt user to select ports for brute-forcing."""
    if not brute_forceable_ports:
        return []

    print(f"\n{Colors.OKBLUE}Select ports to brute-force (e.g. port number like '22'): {Colors.END}")
    selection = input(f"{Colors.OKBLUE}Enter your choice: {Colors.END}").strip()
    
    selected_ports = []
    if re.match(r'^\d+$', selection):  # Single port number
        port = int(selection)
        if port in brute_forceable_ports:
            selected_ports.append(port)
        else:
            print(f"{Colors.FAIL}[!] Invalid port: {port}. Must be one of the detected ports.{Colors.END}")
    elif re.match(r'^\d+(,\d+)*$', selection):  # Comma-separated indices
        indices = [int(i) for i in selection.split(',')]
        if all(1 <= i <= len(brute_forceable_ports) for i in indices):
            selected_ports = [brute_forceable_ports[i-1] for i in indices]
        else:
            print(f"{Colors.FAIL}[!] Invalid selection. Must be valid indices (1-{len(brute_forceable_ports)}).{Colors.END}")
    else:
        print(f"{Colors.FAIL}[!] Invalid input. Use indices (e.g., '1,2') or a single port number.{Colors.END}")

    return selected_ports

def perform_brute_force(target_ip: str, service: dict, username_list: str, password_list: str, threads: int = 4) -> tuple[list, str]:
    """Runs Hydra for brute-forcing on the specified service."""
    try:
        command = ["hydra", "-L", username_list, "-P", password_list, "-t", str(threads), "-f", f"{service['name']}://{target_ip}:{service['port']}"]

        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=loading_spinner, args=(stop_event,))
        spinner_thread.start()

        result = subprocess.run(command, capture_output=True, text=True, timeout=600)

        stop_event.set()
        spinner_thread.join()

        findings = []
        finding_regex = re.compile(r"\[(\d+)\]\[(.+?)\]\s+host:\s+(.+?)\s+login:\s+(.+?)\s+password:\s+(.+)")
        for line in result.stdout.splitlines():
            match = finding_regex.match(line)
            if match:
                port, service_name, host, login, password = match.groups()
                findings.append({"port": port, "service": service_name, "host": host, "login": login, "password": password})

        return findings, result.stderr.strip()

    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}[!] Error: Brute-force check for {service['description']} timed out after 10 minutes.{Colors.END}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}[!] Brute-force check for {service['description']} failed: {e.stderr.strip()}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] An unexpected error occurred during brute-force check for {service['description']}: {e}{Colors.END}")
    finally:
        stop_event.set()
        spinner_thread.join()
    return [], ""

def access_service(target_ip: str, service: dict, login: str, password: str) -> None:
    """Attempt to access the service with the provided credentials."""
    if not check_tools(service["access_cmd"](target_ip, login, password)[0]):
        print(f"{Colors.FAIL}[!] Cannot access {service['description']} due to missing tool.{Colors.END}")
        log_access_attempt(target_ip, service, login, password, "Failed: Missing Tool")
        return

    print(f"{Colors.OKBLUE}[*] Attempting to access {service['description']} (Port {service['port']}) with login: {login}, password: {password}...{Colors.END}")
    cmd = service["access_cmd"](target_ip, login, password)
    output = run_command(cmd)
    if "failed" in output.lower() or "Error" in output:
        print(f"{Colors.FAIL}[!] Access failed: {output}{Colors.END}")
        log_access_attempt(target_ip, service, login, password, "Failed")
    else:
        print(f"{Colors.OKGREEN}[*] Access attempt output: {output}{Colors.END}")
        log_access_attempt(target_ip, service, login, password, "Successful")

def loading_spinner(stop_event):
    """Display a loading spinner until stop_event is set."""
    spinner = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{Colors.OKBLUE}[*] Performing check... {spinner[i % 4]}{Colors.END}")
        sys.stdout.flush()
        time.sleep(0.2)
        i += 1
    sys.stdout.write("\r" + " " * 50 + "\r")

def display_findings(findings: list, service: dict, target_ip: str) -> None:
    """Display parsed findings in a tabular format and prompt for access."""
    if not findings:
        print(f"{Colors.OKGREEN}[*] No successful logins found for {service['description']}. Service is secure against tested credentials.{Colors.END}")
        return

    headers = ["Port", "Service", "Host", "Login", "Password"]
    table_data = [[f["port"], f["service"], f["host"], f["login"], f["password"]] for f in findings]
    table_str = tabulate(table_data, headers=headers, tablefmt="grid", stralign="left")
    print(f"{Colors.FAIL}{table_str}{Colors.END}")
    print(f"{Colors.FAIL}[!] Warning: These credentials were successful for {service['description']}. Change them immediately!{Colors.END}")

    for finding in findings:
        access_prompt = input(f"{Colors.OKBLUE}Proceed with accessing {service['description']} (Port {service['port']}) using login: {finding['login']}, password: {finding['password']}? (yes/no): {Colors.END}").lower()
        if access_prompt == "yes":
            access_service(target_ip, service, finding["login"], finding["password"])

def save_results_auto(findings: list, target_ip: str, service: dict) -> None:
    """Save brute-force results to JSON and CSV files."""
    if not findings:
        return

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base = f"brute_force_{target_ip}_{service['name']}_{timestamp}"

    json_file = f"{base}.json"
    with open(json_file, "w") as jf:
        json.dump({"target_ip": target_ip, "service": service['description'], "port": service['port'], "timestamp": timestamp, "findings": findings}, jf, indent=2)

    csv_file = f"{base}.csv"
    with open(csv_file, "w", newline="") as cf:
        writer = csv.DictWriter(cf, fieldnames=["port", "service", "host", "login", "password"])
        writer.writeheader()
        for r in findings:
            writer.writerow({
                "port": r.get("port", ""),
                "service": r.get("service", ""),
                "host": r.get("host", ""),
                "login": r.get("login", ""),
                "password": r.get("password", "")
            })

    print(f"{Colors.OKGREEN}[*] Report saved: {json_file} and {csv_file}{Colors.END}")

def main():
    print(BANNER)

    # Check required tools
    if not all(check_tools(tool) for tool in ["nmap", "hydra"]):
        sys.exit(1)

    target_ip = input(f"{Colors.OKBLUE}Enter an IP address you are authorized to check: {Colors.END}")
    if not validate_ip(target_ip):
        sys.exit(1)

    if not require_positive_authorization(target_ip, "Brute-Force Check"):
        sys.exit(1)

    # Scan for open ports
    open_ports = scan_open_ports(target_ip)
    if not open_ports:
        print(f"{Colors.OKGREEN}[*] Exiting as no brute-forceable ports were found.{Colors.END}")
        sys.exit(0)

    # Select ports to brute-force
    selected_ports = select_ports(open_ports)
    if not selected_ports:
        print(f"{Colors.OKGREEN}[*] No ports selected for brute-forcing. Exiting.{Colors.END}")
        sys.exit(0)

    # Wordlist input
    default_username_list = "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
    default_password_list = "/usr/share/wordlists/rockyou.txt"
    
    username_list = input(f"{Colors.OKBLUE}Enter path to username list [default: {default_username_list}]: {Colors.END}") or default_username_list
    if not os.path.exists(username_list):
        print(f"{Colors.FAIL}[!] Username list '{username_list}' not found.{Colors.END}")
        sys.exit(1)

    password_list = input(f"{Colors.OKBLUE}Enter path to password list [default: {default_password_list}]: {Colors.END}") or default_password_list
    if not os.path.exists(password_list):
        print(f"{Colors.FAIL}[!] Password list '{password_list}' not found.{Colors.END}")
        sys.exit(1)

    threads = input(f"{Colors.OKBLUE}Enter number of threads (1-16, default: 4): {Colors.END}") or "4"
    try:
        threads = int(threads)
        if not 1 <= threads <= 16:
            print(f"{Colors.FAIL}[!] Invalid thread count. Must be between 1 and 16.{Colors.END}")
            sys.exit(1)
    except ValueError:
        print(f"{Colors.FAIL}[!] Invalid thread count. Must be a number.{Colors.END}")
        sys.exit(1)

    # Perform brute-force on selected ports
    all_findings = []
    for port in selected_ports:
        service = SERVICES[str(port)]
        print(f"\n{Colors.OKBLUE}[*] Performing brute-force check on {service['description']} (Port {port})...{Colors.END}")
        findings, error_log = perform_brute_force(target_ip, service, username_list, password_list, threads)
        display_findings(findings, service, target_ip)
        if error_log:
            print(f"{Colors.WARNING}[!] Error Log for {service['description']}: {error_log}{Colors.END}")
        all_findings.extend(findings)

    # Save results if any findings
    if all_findings:
        save_prompt = input(f"{Colors.OKBLUE}Save report to JSON and CSV files? (yes/no): {Colors.END}").lower()
        if save_prompt == "yes":
            for port in selected_ports:
                service = SERVICES[str(port)]
                service_findings = [f for f in all_findings if f["port"] == str(port)]
                if service_findings:
                    save_results_auto(service_findings, target_ip, service)
        else:
            print(f"{Colors.WARNING}[!] Report not saved.{Colors.END}")

    print(f"{Colors.OKGREEN}[*] Brute-force checks completed for {target_ip}.{Colors.END}")

if __name__ == "__main__":
    main()
