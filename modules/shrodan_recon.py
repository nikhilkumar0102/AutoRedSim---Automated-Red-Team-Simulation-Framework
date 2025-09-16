import json
import os
import csv
import sys
from datetime import datetime
import configparser

# --- Dependency Check ---
try:
    import shodan
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
    from rich import print as rprint
except ImportError:
    print("Error: Required Python libraries are not installed.")
    print("Please run: pip install shodan rich requests")
    sys.exit(1)

class ShodanRecon:
    def __init__(self, api_key, webhook_url=None):
        try:
            self.api = shodan.Shodan(api_key)
            self.api.info()  # Validate API key
        except shodan.APIError as e:
            rprint(f"[red]Shodan API Error: {e}[/red]")
            rprint("[red]Please verify your API key in config.ini.[/red]")
            sys.exit(1)

        self.webhook_url = webhook_url
        self.console = Console()
        self.baseline_dir = "baselines"
        os.makedirs(self.baseline_dir, exist_ok=True)
        self.dorks = [
            {"name": "Exposed Security Cameras", "query": 'port:554 "200 OK" "Server: Webcam"'},
            {"name": "Unsecured MongoDB", "query": 'port:27017 product:"MongoDB"'},
            {"name": "Unsecured Elasticsearch", "query": 'port:9200 product:"Elastic"'},
            {"name": "Exposed RDP Servers", "query": 'port:3389 has_screenshot:true'},
            {"name": "Industrial Control Systems", "query": 'product:"Schneider Electric" OR product:"Siemens"'},
        ]

    def get_api_info(self):
        try:
            return self.api.info()
        except shodan.APIError as e:
            self.console.print(f"[red]Error: {e}[/red]")
            return None

    def confirm_action(self, action):
        info = self.get_api_info()
        if info:
            rprint(f"[yellow]Search credits: {info['query_credits']}, Scan credits: {info['scan_credits']}[/yellow]")
        return input(f"Proceed with {action}? (y/n): ").lower() == 'y'

    def comprehensive_host_profile(self):
        ip = input("Enter IP address: ")
        if not self.confirm_action("host profile lookup"):
            return
        try:
            host = self.api.host(ip)
            self.display_host_profile(host)
            self.export_results([host], f"host_profile_{ip}")
        except shodan.APIError as e:
            self.console.print(f"[red]Error: {e}[/red]")

    def display_host_profile(self, host):
        table = Table(title=f"Host Profile: {host.get('ip_str')}")
        table.add_column("Field")
        table.add_column("Value")

        # Basic Info
        table.add_row("IP", host.get('ip_str', 'N/A'))
        table.add_row("Organization", host.get('org', 'N/A'))
        table.add_row("ISP", host.get('isp', 'N/A'))
        table.add_row("Country", host.get('location', {}).get('country_name', 'N/A'))
        table.add_row("City", host.get('location', {}).get('city', 'N/A'))
        table.add_row("Hostnames", ", ".join(host.get('hostnames', ['N/A'])))

        # Ports and Services
        ports_table = Table(title="Open Ports & Services")
        ports_table.add_column("Port")
        ports_table.add_column("Service")
        ports_table.add_column("Version")
        ports_table.add_column("Vulnerabilities")
        for item in host.get('data', []):
            vulns = ", ".join([v for v in item.get('vulns', {}).keys()]) if item.get('vulns') else "None"
            ports_table.add_row(
                str(item['port']),
                item.get('product', 'Unknown'),
                item.get('version', 'N/A'),
                vulns
            )
        self.console.print(table)
        self.console.print(ports_table)

    def organization_asset_discovery(self):
        org_input = input("Enter organization name (e.g., Google LLC) or domain (e.g., example.com): ")
        query = f'org:"{org_input}"' if " " in org_input else f"hostname:{org_input}"
        if not self.confirm_action("organization asset discovery"):
            return
        try:
            results = self.api.search(query)
            self.display_organization_summary(results, org_input)
            self.export_results(results['matches'], f"org_assets_{org_input.replace(' ', '_')}")
        except shodan.APIError as e:
            self.console.print(f"[red]Error: {e}[/red]")

    def display_organization_summary(self, results, org_input):
        rprint(f"[bold green]Total Assets Found: {results['total']}[/bold green]")
        services = Counter(m.get('product', 'Unknown') for m in results['matches'])
        countries = Counter(m.get('location', {}).get('country_name', 'Unknown') for m in results['matches'])
        ips = [m['ip_str'] for m in results['matches']]

        self.console.print(Panel("Top 5 Services", expand=False, border_style="blue"))
        self.display_top_bar(services.most_common(5))
        self.console.print(Panel("Top 5 Countries", expand=False, border_style="blue"))
        self.display_top_bar(countries.most_common(5))
        self.console.print(Panel(f"Discovered IPs for {org_input}", expand=False, border_style="blue"))
        for ip in ips[:10]:  # Limit to 10 IPs for display
            self.console.print(f"- {ip}")

    def vulnerability_search(self):
        cve = input("Enter CVE (e.g., CVE-2021-44228): ").upper()
        query = f'vuln:{cve}'
        if not self.confirm_action("vulnerability search"):
            return
        try:
            results = self.api.search(query)
            details = self.get_cve_details(cve)
            self.display_vulnerability_results(results, cve, details)
            self.export_vuln_results(results['matches'], cve, details)
        except shodan.APIError as e:
            self.console.print(f"[red]Error: {e}[/red]")

    def get_cve_details(self, cve):
        rprint("[cyan]Fetching CVE details from NVD...[/cyan]")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            if 'vulnerabilities' in data and data['vulnerabilities']:
                vuln = data['vulnerabilities'][0]['cve']
                cvss_metrics = vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                return {
                    'cvss': cvss_metrics.get('cvssData', {}).get('baseScore', 'N/A'),
                    'severity': cvss_metrics.get('cvssData', {}).get('baseSeverity', 'N/A'),
                    'summary': vuln.get('descriptions', [{}])[0].get('value', 'No summary'),
                    'link': f"https://nvd.nist.gov/vuln/detail/{cve}"
                }
            return {'cvss': 'N/A', 'severity': 'N/A', 'summary': 'CVE not found', 'link': ''}
        except Exception:
            return {'cvss': 'Error', 'severity': 'Error', 'summary': 'Failed to fetch', 'link': ''}

    def display_vulnerability_results(self, results, cve, details):
        rprint(Panel(f"CVSS: {details['cvss']} ({details['severity']})\nSummary: {details['summary']}",
                     title=f"Vulnerability Details for {cve}", border_style="magenta"))
        table = Table(title=f"Vulnerable Hosts for {cve} (Found: {results['total']})")
        table.add_column("IP")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Country")
        for match in results['matches'][:20]:
            table.add_row(
                match['ip_str'],
                str(match['port']),
                match.get('product', 'Unknown'),
                match.get('location', {}).get('country_name', 'N/A')
            )
        self.console.print(table)

    def shodan_dorks_library(self):
        self.console.print(Panel("Shodan Dorks Library", expand=False, border_style="green"))
        for i, dork in enumerate(self.dorks, 1):
            self.console.print(f"{i}. {dork['name']}")
        try:
            choice = int(input("Select dork: ")) - 1
            if 0 <= choice < len(self.dorks):
                query = self.dorks[choice]['query']
                rprint(f"[cyan]Executing dork: {query}[/cyan]")
                if not self.confirm_action("dork search"): return
                results = self.api.search(query)
                self.display_search_results(results, self.dorks[choice]['name'])
                self.export_results(results['matches'], self.dorks[choice]['name'].replace(' ', '_'))
        except (ValueError, IndexError):
            self.console.print("[red]Invalid choice.[/red]")
        except shodan.APIError as e:
            self.console.print(f"[red]Error: {e}[/red]")

    def display_search_results(self, results, title):
        table = Table(title=f"Results for '{title}' (Found: {results['total']})")
        table.add_column("IP")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("Country")
        for match in results['matches'][:20]:
            table.add_row(
                match['ip_str'],
                str(match['port']),
                match.get('product', 'Unknown'),
                match.get('location', {}).get('country_name', 'N/A')
            )
        self.console.print(table)

    def target_monitoring(self):
        target = input("Enter IP or network range to monitor (e.g., 192.168.1.1 or 192.168.1.0/24): ")
        baseline_file = os.path.join(self.baseline_dir, f"{target.replace('/', '_')}.json")

        if os.path.exists(baseline_file):
            with open(baseline_file, 'r') as f:
                baseline = json.load(f)
            if not self.confirm_action("monitoring scan"):
                return
            current = self.api.host(target) if '/' not in target else self.api.search(f"net:{target}")
            changes = self.detect_changes(baseline, current)
            if changes:
                rprint("[yellow]Changes Detected:[/yellow]")
                for change in changes:
                    rprint(change)
                if self.webhook_url:
                    self.send_alert(changes)
        else:
            if not self.confirm_action("baseline creation"):
                return
            data = self.api.host(target) if '/' not in target else self.api.search(f"net:{target}")
            with open(baseline_file, 'w') as f:
                json.dump(data, f)
            rprint("[green]Baseline created for {target}.[/green]")

    def detect_changes(self, baseline, current):
        changes = []
        if 'data' in baseline and 'data' in current:
            base_ports = {item['port'] for item in baseline['data']}
            curr_ports = {item['port'] for item in current['data']}
            new_ports = curr_ports - base_ports
            closed_ports = base_ports - curr_ports
            if new_ports:
                changes.append(f"New ports opened: {', '.join(map(str, new_ports))}")
            if closed_ports:
                changes.append(f"Ports closed: {', '.join(map(str, closed_ports))}")
        elif 'total' in baseline and 'total' in current:
            if baseline['total'] != current['total']:
                changes.append(f"Host count changed from {baseline['total']} to {current['total']}")
        return changes

    def send_alert(self, changes):
        payload = {"content": f"Shodan Alert [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]:\n" + "\n".join(changes)}
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            rprint("[green]Alert sent successfully.[/green]")
        except Exception as e:
            rprint(f"[red]Alert failed: {e}[/red]")

    def export_results(self, data, name):
        if not data:
            rprint("[yellow]No data to export.[/yellow]")
            return
        format_choice = input("Export format (csv/json) or skip (Enter): ").lower()
        if not format_choice:
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}.{format_choice}"
        if format_choice == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
        elif format_choice == 'csv':
            keys = {k for item in data for k in item.keys()}
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(keys))
                writer.writeheader()
                writer.writerows(data)
        rprint(f"[green]Exported to {filename}[/green]")

    def export_vuln_results(self, data, cve, details):
        if not data:
            rprint("[yellow]No vulnerable hosts to export.[/yellow]")
            return
        format_choice = input("Export format (csv/json) or skip (Enter): ").lower()
        if not format_choice:
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vuln_{cve}_{timestamp}.{format_choice}"
        export_data = [
            {
                'ip': m['ip_str'],
                'port': m['port'],
                'cve': cve,
                'cvss': details['cvss'],
                'severity': details['severity'],
                'summary': details['summary'],
                'link': details['link']
            } for m in data
        ]
        if format_choice == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=4)
        elif format_choice == 'csv':
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=export_data[0].keys())
                writer.writeheader()
                writer.writerows(export_data)
        rprint(f"[green]Exported to {filename}[/green]")

    def menu(self):
        while True:
            self.console.print(Panel("Shodan Intelligence Framework", expand=False, border_style="bold green"))
            options = [
                "1. Comprehensive Host Profile",
                "2. Organization Asset Discovery",
                "3. Vulnerability (CVE) Search",
                "4. Shodan Dorks Library",
                "5. Target Monitoring & Alerting",
                "6. Exit"
            ]
            for opt in options:
                self.console.print(opt)
            choice = input("Select option: ")
            actions = {
                '1': self.comprehensive_host_profile,
                '2': self.organization_asset_discovery,
                '3': self.vulnerability_search,
                '4': self.shodan_dorks_library,
                '5': self.target_monitoring
            }
            if choice in actions:
                actions[choice]()
            elif choice == '6':
                rprint("[blue]Exiting Shodan Intelligence Framework. Stay secure.[/blue]")
                break
            else:
                self.console.print("[red]Invalid choice.[/red]")

def check_config_file():
    """Checks for config.ini and creates a template if missing."""
    if not os.path.exists('config.ini'):
        rprint("[yellow]Configuration file 'config.ini' not found.[/yellow]")
        rprint("[yellow]Creating a template...[/yellow]")
        config = configparser.ConfigParser()
        config['shodan'] = {'api_key': 'YOUR_SHODAN_API_KEY_HERE'}
        config['alert'] = {'webhook_url': 'YOUR_WEBHOOK_URL_HERE (Optional)'}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        rprint("[green]Created 'config.ini'. Please update with your Shodan API key.[/green]")
        sys.exit(0)

if __name__ == "__main__":
    check_config_file()
    config = configparser.ConfigParser()
    config.read('config.ini')
    api_key = config.get('shodan', 'api_key', fallback=None)
    webhook_url = config.get('alert', 'webhook_url', fallback=None)

    if not api_key or api_key == 'YOUR_SHODAN_API_KEY_HERE':
        rprint("[red]API key missing or invalid in config.ini.[/red]")
        rprint("[red]Please edit config.ini with a valid Shodan API key.[/red]")
        sys.exit(1)
    else:
        recon = ShodanRecon(api_key, webhook_url)
        recon.menu()
