import subprocess
import xml.etree.ElementTree as ET
import json
import os
from datetime import datetime
import tempfile
import time
import sys
import threading
import textwrap
import logging
import re
from rich.table import Table

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

# A list to store live hosts found during discovery
live_hosts = []

# Setup logging to hide background details
logging.basicConfig(filename='autorecon.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def confirm_authorization():
    """Prompt user to confirm they have permission to scan."""
    response = input(f"{Colors.WARNING}Do you have explicit authorization to conduct this operation? (yes/no): {Colors.END}").lower()
    if response != "yes":
        print(f"{Colors.FAIL}[!] Mission aborted. Authorization not confirmed.{Colors.END}")
        exit(1)

def loading_spinner(stop_event):
    """Display a loading spinner until stop_event is set."""
    spinner = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{Colors.OKBLUE}[*] Scanning in progress... {spinner[i % 4]}{Colors.END}")
        sys.stdout.flush()
        time.sleep(0.2)
        i += 1
    sys.stdout.write("\r" + " " * 50 + "\r")  # Clear line

def run_nmap_scan(target, is_list_scan, scan_type, ports, base_filename=None, save_full_report=False):
    """Run Nmap silently, logging details to file."""
    temp_xml_file = tempfile.NamedTemporaryFile(delete=False, suffix=".xml").name
    
    if save_full_report and base_filename:
        command = ["nmap", "-oA", base_filename]
        xml_path_for_parser = f"{base_filename}.xml"
    else:
        command = ["nmap", "-oX", temp_xml_file]
        xml_path_for_parser = temp_xml_file

    scan_args = {
        'discovery': ["-sn"], 'firewall-probe': ["-sA"],
        'comprehensive-tcp': ["-sS", "-A", "-T4"], 'udp-top-ports': ["-sU", "--top-ports", "50"],
        'vuln-scan': ["-sV", "--script=vuln", "-T4"]
    }
    command.extend(scan_args.get(scan_type, []))

    if ports:
        if ports == "-p-":
            command.append("-p-")
        else:
            command.extend(["-p", ports])
    
    if is_list_scan:
        command.extend(["-iL", target])
    else:
        command.append(target)
    
    logger.info(f"Executing Nmap command: {' '.join(command)}")
    print(f"\n{Colors.OKBLUE}[*] Configuring '{scan_type}' scan profile...{Colors.END}")
    if ports:
        print(f"{Colors.OKBLUE}[*] Targeting ports: {ports}{Colors.END}")
    
    # Start spinner
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=loading_spinner, args=(stop_event,))
    spinner_thread.start()
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        stop_event.set()
        spinner_thread.join()
        logger.info(f"Scan completed for target: {target}")
        if save_full_report: 
            print(f"{Colors.OKGREEN}[*] Scan completed. Full reports saved as '{base_filename}.nmap' and '{base_filename}.xml'{Colors.END}")
        else: 
            print(f"{Colors.OKGREEN}[*] Scan completed.{Colors.END}")
        return xml_path_for_parser
    except subprocess.CalledProcessError as e:
        stop_event.set()
        spinner_thread.join()
        logger.error(f"Nmap scan failed: {e.stderr.strip() if e.stderr else str(e)}")
        print(f"{Colors.FAIL}[!] Nmap scan failed. Check logs for details.{Colors.END}")
        if os.path.exists(temp_xml_file):
            os.remove(temp_xml_file)
        return None
    except FileNotFoundError:
        stop_event.set()
        spinner_thread.join()
        logger.error("Nmap command not found. Is Nmap installed and in your system's PATH?")
        print(f"{Colors.FAIL}[!] Error: 'nmap' command not found. Is Nmap installed?{Colors.END}"); exit(1)

def parse_xml_findings(xml_file):
    """Parse Nmap XML to find hosts, ports, states, services, and NSE script outputs."""
    try:
        tree = ET.parse(xml_file)
        findings = []
        for host in tree.findall("host"):
            if host.find("status").get("state") == "up":
                host_info = {"host": host.find("address").get("addr"), "status": "up", "ports": []}
                for port in host.findall(".//port"):
                    service = port.find("service")
                    port_info = {
                        "port_id": port.get("portid"), "protocol": port.get("protocol"), "state": port.find("state").get("state"),
                        "service": service.get("name", "unknown") if service else "unknown", "version": service.get("version", "") if service else "",
                        "vulnerabilities": [{"id": s.get("id"), "output": s.get("output", "").strip()} for s in port.findall("script")]
                    }
                    host_info["ports"].append(port_info)
                findings.append(host_info)
        return findings
    except (ET.ParseError, FileNotFoundError): return []

def get_scan_target():
    """Lets user choose between scanning a single host or all discovered hosts."""
    if not live_hosts:
        print(f"\n{Colors.FAIL}[!] No live targets identified. Run a Network Discovery (Option 1) first.{Colors.END}")
        return None, False

    print(f"\n{Colors.HEADER}--- Target Selection ---{Colors.END}")
    print("1. Scan a specific host from the list.")
    print("2. Scan ALL discovered hosts.")
    choice = input("Choose an option: ")

    if choice == '1':
        for i, host in enumerate(live_hosts, 1): print(f"  {i}. {host}")
        try:
            host_choice = int(input("Choose a target by number: "))
            if 1 <= host_choice <= len(live_hosts):
                return live_hosts[host_choice - 1], False
            else:
                print(f"{Colors.FAIL}[!] Invalid number.{Colors.END}"); return None, False
        except ValueError:
            print(f"{Colors.FAIL}[!] Invalid input.{Colors.END}"); return None, False
    elif choice == '2':
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        temp_file.writelines(f"{host}\n" for host in live_hosts)
        temp_file.close()
        print(f"{Colors.OKGREEN}[*] All {len(live_hosts)} hosts will be scanned.{Colors.END}")
        return temp_file.name, True
    else:
        print(f"{Colors.FAIL}[!] Invalid option.{Colors.END}"); return None, False

def perform_discovery():
    """Phase 1: Find live hosts and store them in memory."""
    global live_hosts
    target = input(f"{Colors.OKBLUE}Enter the target network range (e.g., 192.168.1.0/24): {Colors.END}")
    if not target: print(f"{Colors.FAIL}[!] Target cannot be empty.{Colors.END}"); return

    xml_file = run_nmap_scan(target, False, 'discovery', None)
    if xml_file:
        findings = parse_xml_findings(xml_file)
        if os.path.exists(xml_file): os.remove(xml_file)
        live_hosts = [host['host'] for host in findings if host['status'] == 'up']
        if live_hosts:
            print(f"\n{Colors.OKGREEN}[+] Discovery Complete. Live targets acquired:{Colors.END}")
            for host in live_hosts: print(f"  - {host}")
        else:
            print(f"\n{Colors.WARNING}[-] No live hosts found.{Colors.END}")

def display_tabular_report(findings, scan_type):
    """
    Displays a clean summary table and then a detailed, parsed vulnerability report.
    """
    if not findings:
        print(f"{Colors.WARNING}[-] No findings to report.{Colors.END}")
        return

    print(f"\n{Colors.HEADER}--- {scan_type.replace('-', ' ').title()} Dashboard Report ---{Colors.END}")
    
    for host in findings:
        print(f"\n{Colors.BOLD}Host: {host['host']} (Status: {host['status']}){Colors.END}")
        
        if not host['ports']:
            print("  No open ports found for this host.")
            continue

        # --- Part 1: Display the clean summary table of open ports ---
        table = Table(show_lines=True, header_style="bold magenta")
        table.add_column("Port", style="cyan")
        table.add_column("Protocol", style="white")
        table.add_column("State", style="white")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="white")

        open_ports_exist = False
        for port in host['ports']:
            if port['state'] == 'open':
                open_ports_exist = True
                table.add_row(
                    port.get('port_id', 'N/A'),
                    port.get('protocol', 'N/A'),
                    port.get('state', 'N/A'),
                    port.get('service', 'N/A'),
                    port.get('version', 'N/A')
                )
        
        if open_ports_exist:
            from rich.console import Console
            console = Console()
            console.print(table)
        else:
            print("  No open ports found for this host.")

        # --- Part 2: Display the parsed and highlighted vulnerability details ---
        # This section only runs if vulnerabilities were found
        has_vulns = any(p.get('vulnerabilities') for p in host['ports'])
        if "Vulnerability" in scan_type and has_vulns:
            print(f"\n{Colors.HEADER}Vulnerability Details:{Colors.END}")
            for port in host['ports']:
                if port.get('vulnerabilities'):
                    print(f"\n  {Colors.BOLD}Port {port['port_id']} - {port['service']}{Colors.END}")
                    for vuln in port['vulnerabilities']:
                        print(f"    {Colors.OKGREEN}[+] Script: {vuln['id']}{Colors.END}")
                        
                        # Parse the raw output to extract key details
                        output = vuln['output']
                        state = next((line.split(":", 1)[1].strip() for line in output.split('\n') if "State:" in line), "N/A")
                        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', output)
                        cve_id = cve_match.group(0) if cve_match else "N/A"
                        
                        # Simple summary - often the first descriptive line
                        summary = next((line.strip() for line in output.split('\n') if line.strip() and ":" not in line), "No summary available.")

                        # Highlight the state based on severity
                        state_color = Colors.FAIL if "VULNERABLE" in state.upper() else Colors.WARNING
                        print(f"      {Colors.BOLD}State: {state_color}{state}{Colors.END}")
                        print(f"      {Colors.BOLD}CVE ID: {Colors.WARNING}{cve_id}{Colors.END}")
                        print(f"      {Colors.BOLD}Summary: {Colors.WARNING}{summary}{Colors.END}")

def perform_vulnerability_scan(target, is_list, initial_findings):
    """Performs targeted or full vulnerability scans based on prior results."""
    if not initial_findings:
        print(f"{Colors.FAIL}[!] Run a Port & Service Scan first to identify open ports.{Colors.END}")
        return

    # Extract the target info from the last scan
    target = initial_findings[0]['host'] if len(initial_findings) == 1 else "all_hosts"
    is_list = len(initial_findings) > 1

    while True:
        print(f"\n{Colors.HEADER}--- Vulnerability Assessment Menu ---{Colors.END}")
        print("1. Scan a specific open port for vulnerabilities.")
        print("2. Scan ALL discovered open ports for vulnerabilities.")
        print("3. Return to Main Menu.")
        choice = input("Select operation: ")

        if choice == '1':
            while True: # Loop for scanning specific ports
                
                # --- NEW: DISPLAY PORTS IN A FORMATTED TABLE ---
                from rich.console import Console
                console = Console()
                ports_table = Table(title="Discovered Open Ports & Services", show_lines=True, header_style="bold magenta")
                ports_table.add_column("Port", style="cyan")
                ports_table.add_column("Service", style="yellow")
                ports_table.add_column("Version", style="white")

                open_port_ids = []
                for host in initial_findings:
                    for port in host['ports']:
                        if port['state'] == 'open':
                            open_port_ids.append(port['port_id'])
                            ports_table.add_row(
                                port.get('port_id', 'N/A'),
                                port.get('service', 'N/A'),
                                port.get('version', 'N/A')
                            )
                
                console.print(ports_table)
                # --- END OF NEW TABLE DISPLAY ---

                port_choice = input(f"Enter port to scan, or type 'back' to return: ").strip().lower()
                if port_choice == 'back':
                    break
                
                if port_choice in open_port_ids:
                    xml_file = run_nmap_scan(target, is_list, 'vuln-scan', port_choice)
                    if xml_file:
                        findings = parse_xml_findings(xml_file)
                        if os.path.exists(xml_file): os.remove(xml_file)
                        display_tabular_report(findings, f"Vulnerability Scan on Port {port_choice}")
                        if input(f"{Colors.OKBLUE}[?] Save these results? (yes/no): {Colors.END}").lower() == 'yes':
                            target_name = "all_hosts" if is_list else target.replace('.', '_')
                            save_scan_results(findings, f"vuln_scan_port_{port_choice}", target_name)
                else:
                    print(f"{Colors.FAIL}[!] Invalid port selected.{Colors.END}")

        elif choice == '2':
            all_open_ports = sorted({p['port_id'] for h in initial_findings for p in h['ports'] if p['state'] == 'open'}, key=int)
            if not all_open_ports:
                print(f"{Colors.WARNING}[-] No open ports were found to scan.{Colors.END}")
                continue
            
            ports_to_scan = ",".join(all_open_ports)
            xml_file = run_nmap_scan(target, is_list, 'vuln-scan', ports_to_scan)
            if xml_file:
                findings = parse_xml_findings(xml_file)
                if os.path.exists(xml_file): os.remove(xml_file)
                display_tabular_report(findings, "Full Vulnerability Scan")
                if input(f"{Colors.OKBLUE}[?] Save these results? (yes/no): {Colors.END}").lower() == 'yes':
                    target_name = "all_hosts" if is_list else target.replace('.', '_')
                    save_scan_results(findings, "full_vuln_scan", target_name)
            break

        elif choice == '3':
            break
        else:
            print(f"{Colors.FAIL}[!] Invalid option.{Colors.END}")

def save_scan_results(findings, scan_type_prefix, target_name):
    """Save scan results to a JSON file."""
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_filename = os.path.join(reports_dir, f"{scan_type_prefix}_{target_name}_{timestamp}.json")
    with open(json_filename, "w") as f:
        json.dump(findings, f, indent=4)
    print(f"{Colors.OKGREEN}[*] Results saved to '{json_filename}'{Colors.END}")

def perform_scan(scan_type, default_ports="-"):
    """Generic function for scans, now with sequential vulnerability scan option."""
    target, is_list = get_scan_target()
    if not target: return

    try:
        ports = input(f"{Colors.OKBLUE}Enter ports (default: {default_ports}) or press Enter: {Colors.END}") or default_ports
        
        save_choice = input(f"\n{Colors.OKBLUE}[?] Save full reports for this scan? (yes/no): {Colors.END}").lower() == 'yes'
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)
        target_name = "all_hosts" if is_list else target.replace('.', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = os.path.join(reports_dir, f"{scan_type}_{target_name}_{timestamp}") if save_choice else None
        
        xml_file = run_nmap_scan(target, is_list, scan_type, ports, base_filename, save_full_report=save_choice)
        
        if xml_file:
            findings = parse_xml_findings(xml_file)
            if not save_choice and os.path.exists(xml_file): os.remove(xml_file)
            
            display_tabular_report(findings, scan_type)

            if save_choice:
                json_filename = os.path.join(reports_dir, f"{scan_type}_{target_name}_{timestamp}.json")
                with open(json_filename, "w") as f: json.dump(findings, f, indent=4)
                print(f"{Colors.OKGREEN}[*] Parsed intelligence saved to '{json_filename}'{Colors.END}")

            # --- NEW SEQUENTIAL LOGIC ---
            if scan_type in ['comprehensive-tcp', 'udp-top-ports'] and findings:
                if input(f"\n{Colors.OKBLUE}[?] Port scan complete. Run a vulnerability scan on discovered ports? (yes/no): {Colors.END}").lower() == 'yes':
                    perform_vulnerability_scan(target, is_list, findings)
            # --- END OF NEW LOGIC ---

    finally:
        if is_list and os.path.exists(target): os.remove(target)

def display_menu():
    print(f"\n{Colors.HEADER}--- RedTeam Reconnaissance Framework ---{Colors.END}")
    print("1. Network Discovery (Find live hosts)")
    print("2. Firewall Probe (Check for filtered ports)")
    print("3. Comprehensive TCP Scan (All ports, OS, Services)")
    print("4. Common UDP Services Scan")
    print("5. Exit")
    return input("Select operation: ")

def main():
    confirm_authorization()
    while True:
        choice = display_menu()
        if choice == '1': perform_discovery()
        elif choice == '2': perform_scan('firewall-probe', '1-1000')
        elif choice == '3': perform_scan('comprehensive-tcp', '-p-')
        elif choice == '4': perform_scan('udp-top-ports', None)
        elif choice == '5': print(f"{Colors.OKBLUE}[*] Exiting framework. Stay stealthy.{Colors.END}"); break
        else: print(f"{Colors.FAIL}[!] Invalid operation selected.{Colors.END}")

if __name__ == "__main__":
    main()
