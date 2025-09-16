import subprocess
import re
from datetime import datetime
import sys
import threading
from colorama import init, Fore, Style
from tabulate import tabulate

# Initialize colorama for colored output
init()

# Simple banner
banner = f"""
{Fore.CYAN}{Style.BRIGHT}=======================================
           Web Vulnerability Scanner
=======================================
{Fore.YELLOW}Use ethically and only on authorized systems!{Style.RESET_ALL}
"""

def run_command(cmd):
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
        return f"{Fore.RED}Scan failed: {e.stderr or e.stdout}{Style.RESET_ALL}"
    except FileNotFoundError:
        return f"{Fore.RED}Error: '{cmd[0]}' not found. Is it installed and in your PATH?{Style.RESET_ALL}"
    except subprocess.TimeoutExpired:
        return f"{Fore.RED}Error: Scan timed out after 5 minutes.{Style.RESET_ALL}"

def parse_nmap_output(output, title):
    """Parses and formats Nmap NSE script output into a tabular format."""
    finding_regex = re.compile(r"^\s*\|_?\s*(.*)", re.MULTILINE)
    matches = finding_regex.findall(output)
    
    headers = ["Finding"]
    table_data = [[match] for match in matches] if matches else [["No specific vulnerabilities detected."]]
    table_str = tabulate(table_data, headers=headers, tablefmt="grid", stralign="left")
    colored_table = f"{Fore.GREEN}=== {title} ==={Style.RESET_ALL}\n" + \
                   (f"{Fore.RED}{table_str}{Style.RESET_ALL}" if matches else f"{Fore.GREEN}No specific vulnerabilities detected.{Style.RESET_ALL}")
    return colored_table

def parse_nikto_output(output):
    """Parses and formats Nikto's specific output into a tabular format."""
    findings = [line.strip() for line in output.splitlines() if line.startswith('+')]
    headers = ["Finding"]
    table_data = [[finding] for finding in findings] if findings else [["No major issues found by Nikto."]]
    table_str = tabulate(table_data, headers=headers, tablefmt="grid", stralign="left")
    colored_table = f"{Fore.GREEN}=== Web Server Vulnerability Scan (Nikto) ==={Style.RESET_ALL}\n" + \
                   (f"{Fore.RED}{table_str}{Style.RESET_ALL}" if findings else f"{Fore.GREEN}No major issues found by Nikto.{Style.RESET_ALL}")
    return colored_table

def cert_scan(target, ports):
    """Performs certificate and TLS vulnerability scan using sslyze."""
    try:
        # Run sslyze with specific scan commands
        sslyze_cmd = [
            "sslyze",
            "--certinfo",
            "--heartbleed",
            "--openssl_ccs",
            "--robot",
            "--sslv2",
            "--sslv3",
            "--tlsv1",
            "--tlsv1_1",
            f"{target}:443"
        ]
        output = run_command(sslyze_cmd)
        if "Error" in output or "failed" in output.lower():
            return f"{Fore.RED}SSLyze scan failed: {output}{Style.RESET_ALL}"

        results = []
        # Parse certificate expiration
        exp_pattern = r"not_after:.*?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+UTC)"
        exp_match = re.search(exp_pattern, output)
        if exp_match:
            exp_date_str = exp_match.group(1)
            try:
                exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d %H:%M:%S UTC")
                current_date = datetime.now()
                status = "expired" if exp_date < current_date else "valid"
                res = f"{status} (expires on {exp_date})"
                color = Fore.RED if "expired" in status else Fore.GREEN
                results.append(["Certificate Expiration", f"{color}{res}{Style.RESET_ALL}"])
            except ValueError:
                results.append(["Certificate Expiration", f"{Fore.RED}Error parsing expiration date{Style.RESET_ALL}"])
        else:
            results.append(["Certificate Expiration", f"{Fore.YELLOW}No expiration information found{Style.RESET_ALL}"])

        # Parse vulnerabilities
        vuln_checks = [
            ("Heartbleed", r"heartbleed.*?\*.*?VULNERABLE", "Vulnerable", "Not Vulnerable"),
            ("OpenSSL CCS Injection", r"openssl_ccs.*?\*.*?VULNERABLE", "Vulnerable", "Not Vulnerable"),
            ("ROBOT Attack", r"robot.*?\*.*?VULNERABLE", "Vulnerable", "Not Vulnerable"),
            ("SSLv2 Support", r"sslv2.*?\*.*?VULNERABLE", "Supported (Vulnerable)", "Not Supported"),
            ("SSLv3 Support", r"sslv3.*?\*.*?VULNERABLE", "Supported (Vulnerable)", "Not Supported"),
            ("TLSv1.0 Support", r"tlsv1\s.*?\*.*?VULNERABLE", "Supported (Vulnerable)", "Not Supported"),
            ("TLSv1.1 Support", r"tlsv1_1.*?\*.*?VULNERABLE", "Supported (Vulnerable)", "Not Supported"),
        ]

        for check_name, vuln_pattern, vuln_text, safe_text in vuln_checks:
            is_vuln = bool(re.search(vuln_pattern, output, re.IGNORECASE))
            res = vuln_text if is_vuln else safe_text
            color = Fore.RED if is_vuln else Fore.GREEN
            results.append([check_name, f"{color}{res}{Style.RESET_ALL}"])

        headers = ["Check", "Result"]
        table_str = tabulate(results, headers=headers, tablefmt="grid", stralign="left")
        return f"{Fore.GREEN}=== Certificate and TLS Scan Results (SSLyze) ==={Style.RESET_ALL}\n{table_str}"

    except Exception as e:
        return f"{Fore.RED}Error during SSLyze scan: {str(e)}{Style.RESET_ALL}"

def scan_worker(target, ports, scan_func, results_dict):
    """A thread worker function to run a scan and store its result."""
    results_dict[scan_func.__name__] = scan_func(target, ports)

def main():
    print(banner)

    target = input(f"{Fore.CYAN}Enter the target website or IP (e.g., example.com): {Style.RESET_ALL}")
    ports = input(f"{Fore.CYAN}Enter ports to scan (default: 80,443): {Style.RESET_ALL}") or "80,443"
    output_file = input(f"{Fore.CYAN}Enter output file to save results (leave blank for none): {Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Select a scan option:{Style.RESET_ALL}")
    print("1. SQL Injection Scan")
    print("2. XSS Scan")
    print("3. Certificate and TLS Vulnerability Scan (SSLyze)")
    print("4. Web Server Vulnerability Scan (Nikto)")
    print("5. Run All Scans")
    choice = input(f"{Fore.CYAN}Enter choice (1-5): {Style.RESET_ALL}")

    scan_map = {
        "1": lambda t, p: parse_nmap_output(run_command(["nmap", "-sV", f"--script=http-sql-injection", f"-p{p}", t]), "SQL Injection Scan Results"),
        "2": lambda t, p: parse_nmap_output(run_command(["nmap", "-sV", f"--script=http-xssed", f"-p{p}", t]), "XSS Scan Results"),
        "3": cert_scan,
        "4": lambda t, p: parse_nikto_output(run_command(["nikto", "-h", t])),
    }

    threads = []
    results = {}
    
    if choice == "5":
        print(f"\n{Fore.BLUE}Starting all scans concurrently...{Style.RESET_ALL}")
        for key, func in scan_map.items():
            thread = threading.Thread(target=scan_worker, args=(target, ports, func, results))
            threads.append(thread)
            thread.start()
    elif choice in scan_map:
        print(f"\n{Fore.BLUE}Starting selected scan...{Style.RESET_ALL}")
        thread = threading.Thread(target=scan_worker, args=(target, ports, scan_map[choice], results))
        threads.append(thread)
        thread.start()
    else:
        print(f"{Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")
        return

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Print results
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Scan Results for {target}:{Style.RESET_ALL}")
    final_report = "\n\n".join(results.values())
    print(final_report)

    # Save to output file if specified
    if output_file:
        clean_report = re.sub(r'\x1b\[[0-9;]*[mK]', '', final_report)
        with open(output_file, "w") as f:
            f.write(f"Scan Report for {target}\n")
            f.write("="*40 + "\n\n")
            f.write(clean_report)
        print(f"{Fore.GREEN}\nResults saved to {output_file}.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
