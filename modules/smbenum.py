import subprocess
import sys
import time
import threading
import re
import os
from rich.table import Table
from rich.console import Console
from rich import print as rprint

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Initialize console for formatted output
console = Console()

# Stylish banner with current date and time
BANNER = "[bold blue]o-~-~ Advanced SMB Share Enumerator ~-~-o[/bold blue]\n[italic]v1.0 | September 16, 2025 12:06 AM IST[/italic]"

def check_smbclient():
    """Verify if smbclient is installed."""
    try:
        subprocess.run(["which", "smbclient"], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        rprint("[red]Error: 'smbclient' is not installed or not in your PATH.[/red]")
        rprint("[red]On Debian/Ubuntu, install it with: sudo apt install smbclient[/red]")
        return False

def normalize_target(target_ip, port=None):
    """Normalize the target IP and port into a usable format."""
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
        rprint("[red]Error: Invalid IP address format.[/red]")
        return None
    return f"//{target_ip}" + (f":{port}" if port else "")

def scan_smb_shares(target, username=None, password=None, verbose=False):
    """Scan SMB shares with optional authentication and real-time output."""
    command = ["smbclient", "-L", target, "-N"]  # Default to null session
    if username and password:
        command.extend(["-U", f"{username}%{password}"])
        command.remove("-N")
    if verbose:
        command.append("-d 3")  # Increase verbosity for debugging

    results = []
    stop_event = threading.Event()

    def process_output(process):
        """Process smbclient output in real-time."""
        while not stop_event.is_set() and process.poll() is None:
            line = process.stdout.readline().strip()
            # We look for lines that contain 'Disk' or 'IPC' to identify shares
            if line and any(keyword in line for keyword in ["Disk", "IPC"]):
                share_info = line.strip()
                if share_info not in results:
                    results.append(share_info)
                    # Print found shares in real-time
                    rprint(f"[green]* Found Share:[/green] {share_info}")

    try:
        # Add a blank line before starting the scan
        rprint() 
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=os.environ.copy())
        output_thread = threading.Thread(target=process_output, args=(process,))
        output_thread.start()

        process.wait(timeout=30)  # 30-second timeout
        stop_event.set()
        output_thread.join()

        # Add a blank line before the final report
        rprint()

        if process.returncode != 0:
            stderr = process.stderr.read().strip()
            
            # Check for specific authentication failure message
            if "The attempted logon is invalid" in stderr or "SPNEGO login failed" in stderr:
                rprint("[bold red][!] AUTHENTICATION FAILED:[/bold red] The username or password provided is incorrect.")
                rprint("[yellow]Please verify the credentials and try again.[/yellow]")
            
            # Check for null session access denied
            elif "NT_STATUS_ACCESS_DENIED" in stderr or "session setup failed" in stderr:
                rprint("[bold green][+] SECURE:[/bold green] Anonymous login (null session) is correctly disabled.")
            
            # Handle all other errors
            else:
                rprint(f"[yellow]Warning: Scan incomplete. Raw Error: {stderr}[/yellow]")     

        elif results:
            rprint("[bold red][!] VULNERABLE: Anonymous login allowed.[/bold red]")
            
            # --- FORMATTED TABLE FOR CLEAN OUTPUT ---
            table = Table(title="Discovered Shares", show_lines=True, header_style="bold magenta")
            table.add_column("Share Name", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Comment", style="white")

            for share_line in results:
                # Split the line by 2 or more spaces to handle formatting
                parts = re.split(r'\s{2,}', share_line.strip())
                share_name = parts[0] if parts else ""
                share_type = parts[1] if len(parts) > 1 else ""
                comment = parts[2] if len(parts) > 2 else ""
                table.add_row(share_name, share_type, comment)
            
            console.print(table)
            # --- END OF TABLE ---

            # Prompt for connection
            connect_choice = input(f"{Colors.WARNING}[?] Would you like to attempt to connect to a share? (yes/no): {Colors.END}").lower()
            if connect_choice == "yes":
                share_name = input(f"{Colors.WARNING}Enter the name of the share to connect to (e.g., tmp): {Colors.END}").strip()
                connect_command = ["smbclient", f"//{target.split('//')[1].split(':')[0]}/{share_name}"]
                if username and password:
                    connect_command.extend(["-U", f"{username}%{password}"])
                try:
                    rprint(f"[green]* Attempting to connect to {share_name}...[/green]")
                    subprocess.run(connect_command, text=True, check=True)
                except subprocess.CalledProcessError as e:
                    rprint(f"[red]Error: Failed to connect to {share_name}. Error: {e}[/red]")
                except Exception as e:
                    rprint(f"[red]Error: Unexpected issue connecting to {share_name}. Error: {e}[/red]")

        else:
            rprint("[yellow]Scan completed, but no accessible shares were found.[/yellow]")

    except subprocess.TimeoutExpired:
        if 'process' in locals(): process.terminate()
        stop_event.set()
        if 'output_thread' in locals(): output_thread.join()
        rprint("[red]Error: Scan timed out after 30 seconds.[/red]")
    except Exception as e:
        stop_event.set()
        if 'output_thread' in locals(): output_thread.join()
        rprint(f"[red]An unexpected error occurred: {e}[/red]")

def main():
    """Main function to run the advanced SMB enumerator."""
    console.print(BANNER)

    if not check_smbclient():
        return

    # --- UPDATED WITH YELLOW HIGHLIGHTS ---
    target_ip = input(f"{Colors.WARNING}Enter an IP address you are authorized to scan: {Colors.END}").strip()
    normalized_target = normalize_target(target_ip)
    if not normalized_target:
        return

    auth_choice = input(f"{Colors.WARNING}Use authentication? (yes/no): {Colors.END}").lower()
    username = password = None
    if auth_choice == "yes":
        username = input(f"{Colors.WARNING}Enter username: {Colors.END}").strip()
        password = input(f"{Colors.WARNING}Enter password: {Colors.END}").strip()

    port = input(f"{Colors.WARNING}Enter custom port (leave blank for default 445): {Colors.END}").strip() or None
    normalized_target = normalize_target(target_ip, port) if port else normalized_target

    verbose = input(f"{Colors.WARNING}Enable verbose mode? (yes/no): {Colors.END}").lower() == "yes"

    # Authorization check remains yellow, as it was before
    confirm = input(f"{Colors.WARNING}Are you authorized to check SMB on '{target_ip}'? (yes/no): {Colors.END}").lower()
    if confirm != "yes":
        rprint("[red]Authorization not confirmed. Exiting.[/red]")
        return
    # --- END OF UPDATE ---

    # Perform scan
    scan_smb_shares(normalized_target, username, password, verbose)

if __name__ == "__main__":
    main()
