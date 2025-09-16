import subprocess
import os
import time
import sys
import threading
import re
from rich.console import Console
from urllib.parse import urlparse

# Initialize console for formatted output
console = Console()

# Stylish banner with current date and time
BANNER = "[bold magenta]~~~ Web Directory Explorer ~~~[/bold magenta]\n[italic green]Unveiling Hidden Paths - v1.0 (Sep 15, 2025, 10:39 PM IST)[/italic green]"

def loading_spinner(stop_event):
    """Display a traditional rotator effect until stop_event is set."""
    rotator = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{Colors.OKBLUE}[*] Scanning directories... {rotator[i % 4]}{Colors.END}")
        sys.stdout.flush()
        time.sleep(0.3)
        i += 1
    sys.stdout.write("\r" + " " * 50 + "\r")  # Clear line

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

def check_gobuster():
    """Verify if gobuster is installed."""
    if os.system("which gobuster > /dev/null 2>&1") != 0:
        console.print("\n[red]Error: gobuster is not installed. Please install it (e.g., 'sudo apt install gobuster').[/red]")
        return False
    return True

def normalize_url(url):
    """Normalize the URL to ensure it has a scheme and valid format."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url

def monitor_progress(stop_event, process, timeout_seconds=30):
    """Monitor if gobuster produces output within the timeout period."""
    start_time = time.time()
    while time.time() - start_time < timeout_seconds and not stop_event.is_set():
        time.sleep(1)
    if not stop_event.is_set():
        console.print(f"\n[red]Error: No directories found after {timeout_seconds} seconds. Terminating scan.[/red]")
        if 'process' in locals():
            process.terminate()
        stop_event.set()

def process_gobuster_output(process, stop_event, normalized_target):
    """Process gobuster output in real-time and display found directories."""
    results = set()  # Use set to avoid duplicates
    while not stop_event.is_set() and process.poll() is None:
        line = process.stdout.readline().strip()  # Already text with text=True
        if line:
            # Match gobuster's default output: URL (Status: code)
            match = re.match(r"^(https?://[^\s]+)\s+\(Status: (\d+)\)", line)
            if match:
                url, status = match.groups()
                if url not in results:  # Avoid duplicate display
                    results.add(url)
                    console.print(f"[green]Found: {url} (Status: {status})[/green]")
            # Fallback for compact output or other modes
            elif line.strip() and not line.startswith("#"):
                path_or_subdomain = line.strip().split()[0]
                full_url = f"{normalized_target.rstrip('/')}/{path_or_subdomain}" if not path_or_subdomain.startswith('http') else path_or_subdomain
                if full_url not in results:
                    results.add(full_url)
                    console.print(f"[green]Found: {full_url} (Status: Unknown)[/green]")

def perform_web_brute():
    """Performs web directory brute-forcing using gobuster with real-time output."""
    console.print(BANNER)
    
    # Check if gobuster is available
    if not check_gobuster():
        return

    # Get and normalize target URL
    target = input("\n[*] Enter the target URL (e.g., example.com or http://example.com): ").strip()
    normalized_target = normalize_url(target)
    if not normalized_target:
        console.print("[red]Error: Invalid URL format. Please include a domain (e.g., example.com).[/red]")
        return

    # Predefined wordlist options
    wordlist_options = {
        "1": "/usr/share/wordlists/dirb/common.txt",
        "2": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "3": "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "4": "custom"
    }
    console.print("\n[bold]Choose a wordlist:[/bold]")
    console.print("1. DIRB Common (small)")
    console.print("2. DirBuster Medium (medium)")
    console.print("3. SecLists Common (large)")
    console.print("4. Custom path")
    wordlist_choice = input("Enter choice (1-4): ").strip()
    wordlist = wordlist_options.get(wordlist_choice, "/usr/share/wordlists/dirb/common.txt")
    if wordlist == "custom":
        wordlist = input("Enter custom wordlist path: ").strip()
    if not os.path.exists(wordlist):
        console.print("[red]Error: Wordlist not found. Using default: /usr/share/wordlists/dirb/common.txt[/red]")
        wordlist = "/usr/share/wordlists/dirb/common.txt"

    # Mode selection
    mode_options = {
        "1": "dir",
        "2": "vhost",
        "3": "dns",
        "4": "fuzz",
        "5": "tftp",
        "6": "s3"
    }
    console.print("\n[bold]Choose a mode:[/bold]")
    console.print("1. Directory/File Enumeration (dir)")
    console.print("2. VHOST Enumeration (vhost - use IP as URL)")
    console.print("3. DNS Subdomain Enumeration (dns)")
    console.print("4. Fuzzing Mode (fuzz - replace FUZZ in URL)")
    console.print("5. TFTP Enumeration (tftp)")
    console.print("6. AWS S3 Bucket Enumeration (s3)")
    mode_choice = input("Enter choice (1-6): ").strip()
    mode = mode_options.get(mode_choice, "dir")

    # Adjust target based on mode
    if mode == "vhost":
        console.print("[yellow]Note: For VHOST mode, use the target IP address (e.g., 192.168.1.1).[/yellow]")
    elif mode == "fuzz":
        fuzz_target = input("Enter URL with FUZZ keyword (e.g., http://example.com/FUZZ): ").strip()
        if not fuzz_target or "FUZZ" not in fuzz_target:
            console.print("[red]Error: Fuzz mode requires 'FUZZ' in the URL.[/red]")
            return
        normalized_target = fuzz_target

    # Define output file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = f"web_brute_{normalized_target.replace('http://', '').replace('https://', '').replace('/', '_')}_{timestamp}.txt"
    log_file = f"gobuster_log_{timestamp}.txt"

    try:
        # Start loading spinner
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=loading_spinner, args=(stop_event,))
        spinner_thread.start()

        # Run gobuster with real-time output
        gobuster_cmd = ["gobuster", mode, "-u", normalized_target, "-w", wordlist, "-k"]  # -k ignores SSL errors
        process = subprocess.Popen(gobuster_cmd, cwd=".", stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy(), text=True)
        
        # Start monitor and output threads
        monitor_thread = threading.Thread(target=monitor_progress, args=(stop_event, process, 30))
        output_thread = threading.Thread(target=process_gobuster_output, args=(process, stop_event, normalized_target))
        monitor_thread.start()
        output_thread.start()

        # Wait for the process to complete or timeout
        process.wait(timeout=300)  # 5-minute overall timeout

        # Stop threads if still running
        stop_event.set()
        spinner_thread.join()
        monitor_thread.join()
        output_thread.join()

        # Collect final results for saving (duplicates handled in real-time)
        results = []
        if process.stderr:
            with open(log_file, "w") as log:
                log.write(process.stderr.read())
        if os.path.exists("gobuster_temp.txt"):
            with open("gobuster_temp.txt", "r", encoding="utf-8") as f:
                for line in f:
                    match = re.match(r"^(https?://[^\s]+)\s+\(Status: (\d+)\)", line.strip())
                    if match:
                        url, status = match.groups()
                        results.append(f"{url} (Status: {status})")
                    elif line.strip() and not line.startswith("#"):
                        path_or_subdomain = line.strip().split()[0]
                        if mode in ["dns", "s3"]:
                            results.append(f"{path_or_subdomain} (Status: N/A)")
                        else:
                            results.append(f"{normalized_target.rstrip('/')}/{path_or_subdomain} (Status: Unknown)")
            os.remove("gobuster_temp.txt")

        # Summary of results
        unique_results = list(set(results))
        if unique_results:
            console.print(f"\n[green]Scan completed! Total items found: {len(unique_results)}.[/green]")
        else:
            console.print(f"[yellow]No additional items found. Check log at {log_file} for details.[/yellow]")

        # Ask user to save results
        save_choice = input("Would you like to save the results to a file? (yes/no): ").lower()
        if save_choice == "yes":
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"Web Brute-Forcing Results for {normalized_target} - {timestamp} (Mode: {mode})\n")
                f.write("-" * 50 + "\n")
                for result in unique_results:
                    f.write(f"{result}\n")
                f.write("-" * 50 + "\n")
            console.print(f"[green]Results saved to: {output_file}[/green]")
            console.print("[*] Open with a text editor for full details.")

    except subprocess.TimeoutExpired:
        if 'process' in locals(): process.terminate()
        stop_event.set()
        spinner_thread.join()
        monitor_thread.join()
        output_thread.join()
        console.print("[red]Error: Scan timed out after 5 minutes.[/red]")
    except Exception as e:
        stop_event.set()
        spinner_thread.join()
        monitor_thread.join()
        output_thread.join()
        console.print(f"\n[red]An error occurred: {e}[/red]")

if __name__ == "__main__":
    # Authorization check
    confirm = input("Are you authorized to scan this target? (yes/no): ").lower()
    if confirm == "yes":
        perform_web_brute()
    else:
        console.print("[red]Aborted. Authorization required.[/red]")
