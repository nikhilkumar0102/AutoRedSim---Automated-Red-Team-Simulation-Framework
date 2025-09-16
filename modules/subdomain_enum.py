import dns.resolver
import requests
import subprocess
import os
from datetime import datetime
import sys
import time
import threading

class Colors:
    OKBLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

BANNER = f"""{Colors.OKBLUE}{Colors.BOLD}
o-~-~ Subdomain Enumerator ~-~-o
{Colors.END}
"""

print(BANNER)

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

def loading_spinner(stop_event):
    """Display a loading spinner until stop_event is set."""
    spinner = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{Colors.OKBLUE}[*] Enumerating subdomains... {spinner[i % 4]}{Colors.END}")
        sys.stdout.flush()
        time.sleep(0.2)
        i += 1
    sys.stdout.write("\r" + " " * 50 + "\r")  # Clear line

def check_subdomain_takeover(subdomain):
    """Checks for common fingerprints of services vulnerable to takeover."""
    takeover_fingerprints = [
        "There isn't a GitHub Pages site here.",
        "NoSuchBucket",
        "The specified bucket does not exist",
        "herokucdn.com/error-pages/no-such-app.html",
        "Project not found",
        "This domain is not configured"
    ]
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        for fingerprint in takeover_fingerprints:
            if fingerprint in response.text:
                return f"[!] Potential Takeover Vulnerable: {fingerprint}"
    except requests.RequestException:
        return ""  # Ignore connection errors
    return ""

def enumerate_subdomains_dns(domain, wordlist):
    """Enumerates subdomains using dns.resolver."""
    live_subdomains = []
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            ip_addresses = [answer.to_text() for answer in answers]
            takeover_status = check_subdomain_takeover(subdomain)
            if takeover_status:
                print(f"[+] Found Live Subdomain (DNS): {subdomain} -> {', '.join(ip_addresses)}")
                print(f"  {takeover_status}")
            live_subdomains.append((subdomain, ip_addresses, takeover_status))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as e:
            print(f"[-] Error checking {subdomain} (DNS): {e}")
    return live_subdomains

def enumerate_subdomains_subfinder(domain):
    """Enumerates subdomains using subfinder."""
    live_subdomains = []
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-o", "subfinder_temp.txt"], 
                              capture_output=True, text=True, check=True)
        if os.path.exists("subfinder_temp.txt"):
            with open("subfinder_temp.txt", "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]
            for subdomain in subdomains:
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    ip_addresses = [answer.to_text() for answer in answers]
                    takeover_status = check_subdomain_takeover(subdomain)
                    if takeover_status:
                        print(f"[+] Found Live Subdomain (Subfinder): {subdomain} -> {', '.join(ip_addresses)}")
                        print(f"  {takeover_status}")
                    live_subdomains.append((subdomain, ip_addresses, takeover_status))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except Exception as e:
                    print(f"[-] Error checking {subdomain} (Subfinder): {e}")
            os.remove("subfinder_temp.txt")
    except subprocess.CalledProcessError as e:
        print(f"[-] Subfinder failed: {e.stderr}. Falling back to DNS enumeration.")
    except FileNotFoundError:
        print("[-] Subfinder not found. Skipping Subfinder enumeration.")
    return live_subdomains

def display_dashboard(live_subdomains):
    """Displays a dashboard of top domains found."""
    if not live_subdomains:
        print(f"\n{Colors.WARNING}[-] No live subdomains found.{Colors.END}")
        return
    print(f"\n{Colors.OKGREEN}[*] Subdomain Enumeration Dashboard{Colors.END}")
    print(f"{Colors.OKBLUE}{'Subdomain':<30} {'IP Address(es)':<20} {'Takeover Status':<20}{Colors.END}")
    print("-" * 70)
    for subdomain, ips, takeover in live_subdomains[:5]:  # Top 5 for dashboard
        takeover_status = takeover if takeover else "Safe"
        print(f"{subdomain:<30} {', '.join(ips)[:19]:<20} {takeover_status:<20}")
    print("-" * 70)
    print(f"{Colors.OKGREEN}[*] Showing top 5 subdomains. Total found: {len(live_subdomains)}{Colors.END}")

def save_to_file(live_subdomains, domain):
    """Saves results to a readable .txt file."""
    if live_subdomains:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"subdomains_{domain}_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(f"Subdomain Enumeration Results for {domain} - {timestamp}\n")
            f.write("-" * 50 + "\n")
            for subdomain, ips, takeover in live_subdomains:
                f.write(f"Subdomain: {subdomain}\n")
                f.write(f"IP Address(es): {', '.join(ips)}\n")
                f.write(f"Takeover Status: {takeover if takeover else 'Safe'}\n")
                f.write("-" * 50 + "\n")
        print(f"{Colors.OKGREEN}[*] Results saved to {filename}{Colors.END}")

if __name__ == "__main__":
    # --- Authorization Check ---
    target_domain = input("Enter a domain you are authorized to scan: ")
    confirm = input(f"Are you the owner of '{target_domain}' or have explicit permission? (yes/no): ").lower()

    if confirm == 'yes':
        # A small, common wordlist for demonstration, plus top domains
        common_subdomains = [
            "www", "mail", "ftp", "test", "dev", "api", "blog", "shop",
            "admin", "portal", "staging", "vpn", "secure"
        ]
        
        # Start loading spinner
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=loading_spinner, args=(stop_event,))
        spinner_thread.start()

        # Enumerate subdomains using both methods
        dns_subdomains = enumerate_subdomains_dns(target_domain, common_subdomains)
        subfinder_subdomains = enumerate_subdomains_subfinder(target_domain)
        live_subdomains = dns_subdomains + subfinder_subdomains

        # Stop loading spinner
        stop_event.set()
        spinner_thread.join()

        # Remove duplicates based on subdomain name
        unique_subdomains = []
        seen = set()
        for subdomain, ips, takeover in live_subdomains:
            if subdomain not in seen:
                seen.add(subdomain)
                unique_subdomains.append((subdomain, ips, takeover))

        # Display dashboard
        display_dashboard(unique_subdomains)

        # Ask user if they want to save results
        save_choice = input("Would you like to save the results to a file? (yes/no): ").lower()
        if save_choice == 'yes':
            save_to_file(unique_subdomains, target_domain)
    else:
        print("[!] Authorization not confirmed. Exiting.")
