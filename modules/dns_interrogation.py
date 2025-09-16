import sys

# --- Dependency Check ---
try:
    import dns.resolver
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
except ImportError:
    print("Error: Required Python libraries are not installed.")
    print("Please run the following command to install them:")
    print("pip install dnspython rich")
    sys.exit(1)

# For colors and styles
console = Console()

BANNER = "[bold blue]o-~-~ DNS Interrogator ~-~-o[/bold blue]"

def query_dns(domain, record_type):
    """Queries a specific DNS record type for a domain."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [answer.to_text() for answer in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return ["Not found"]
    except Exception as e:
        return [f"Error: {e}"]

def main():
    """Main function to run the DNS interrogation tool."""
    console.print(BANNER)
    
    # --- Authorization Check ---
    target_domain = input("Enter a domain you are authorized to query: ")
    confirm = input(f"Are you authorized to query DNS records for '{target_domain}'? (yes/no): ").lower()

    if confirm != 'yes':
        rprint("[red]Authorization not confirmed. Exiting.[/red]")
        return

    rprint(f"\n[*] Starting DNS interrogation for: [bold green]{target_domain}[/bold green]")
    
    # Define record types to query
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    
    # Create a table to display results
    results_table = Table(title="DNS Interrogation Report", show_lines=True)
    results_table.add_column("Record Type", style="cyan", no_wrap=True)
    results_table.add_column("Results", style="magenta")

    # Query each record type and add to the table
    for r_type in record_types:
        results = query_dns(target_domain, r_type)
        # Join multi-line results (like TXT records) with a newline
        formatted_results = "\n".join(results)
        results_table.add_row(r_type, formatted_results)

    console.print(results_table)

if __name__ == "__main__":
    main()
