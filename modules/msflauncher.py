import subprocess
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

# --- Dependency Check ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("Error: The 'rich' library is not installed.")
    print("Please run: pip install rich")
    sys.exit(1)

console = Console()

# --- Custom Banner ---
BANNER = Panel("[bold cyan]MSFLauncher - Clean Metasploit Session Starter[/bold cyan]",
               title="v1.1",
               border_style="green")

# --- Display Important Commands ---
def display_info():
    """Displays the banner and a table of essential Metasploit commands."""
    console.print(BANNER)
    
    table = Table(title="[bold yellow]Essential Metasploit Commands[/bold yellow]", show_header=False, border_style="blue")
    table.add_column("Command", style="cyan", width=25)
    table.add_column("Description", style="white")

    table.add_row("search [keyword]", "Search for modules (e.g., search eternalblue)")
    table.add_row("use [module_name]", "Select a module to use")
    table.add_row("set [OPTION] [value]", "Set a required option (e.g., set RHOSTS 10.10.10.5)")
    table.add_row("run / exploit", "Execute the selected module")
    
    console.print(table)

def check_msf_installed():
    """Checks if msfconsole is installed and in the system's PATH."""
    try:
        subprocess.run(["msfconsole", "--version"], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        rprint("\n[red][!] Error: 'msfconsole' not found.[/red]")
        rprint("[red]Please ensure the Metasploit Framework is installed and in your system's PATH.[/red]")
        return False

def launch_clean_msf():
    """Launches an interactive msfconsole session without the banner."""
    if not check_msf_installed():
        sys.exit(1)

    rprint("\n[*] Launching clean Metasploit session...")
    
    try:
        # The '-q' flag tells msfconsole to start in quiet mode (no banner).
        subprocess.run(["msfconsole", "-q"])
        
    except KeyboardInterrupt:
        rprint("\n[*] Exiting.")
    except Exception as e:
        rprint(f"\n[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    display_info()
    
    confirm = input("\nPress Enter to launch Metasploit, or 'q' to quit: ").lower()
    if confirm != 'q':
        launch_clean_msf()
    else:
        rprint("[*] Aborted by user.")
