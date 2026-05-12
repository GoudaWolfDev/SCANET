import subprocess
import re
import socket
import json
import sys
import argparse
import concurrent.futures
from datetime import datetime
from mac_vendor_lookup import MacLookup
import nmap
import ipaddress

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
from rich import box

# Initialize Components
console = Console()
scanner = nmap.PortScanner()
mac_db = MacLookup()

# Try to update mac database quietly
try:
    mac_db.update_vendors()
except:
    pass

# ==========================================
# Compact Banner
# ==========================================

BANNER_COMPACT = """[bold red]SCANET [white]V1.0[/white] | [cyan]D33P-X Recon Engine[/cyan][/bold red]
[dim]Developed by: Gouda Nasrallah (جوده نصرالله)[/dim]
"""

def show_help():
    help_text = """
[bold cyan]SCANET Usage Guide:[/bold cyan]
-----------------------------------------
[bold green]Command Line:[/bold green]
  python scanet.py [target] [flags]

[bold green]Flags:[/bold green]
  [yellow]-f, --fast[/yellow]     : Fast scan (Top 100 ports only)
  [yellow]-v, --vuln[/yellow]     : Deep scan + Vulnerability detection (NSE)
  [yellow]-h, --help[/yellow]     : Show this help message

[bold green]Examples:[/bold green]
  python scanet.py 192.168.1.0/24 -f
  python scanet.py 10.0.0.5 -v
"""
    console.print(Panel(help_text, title="[bold red]HELP MENU[/bold red]", border_style="red", box=box.ROUNDED))

class ScanetPro:
    def __init__(self, target, fast=False, vuln=False):
        self.target = target
        self.fast = fast
        self.vuln = vuln
        self.results = []

    def get_vendor(self, mac):
        try:
            return mac_db.lookup(mac)
        except:
            return ""

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""

    def run_discovery(self):
        """Phase 1: Fast Host Discovery"""
        devices = []
        console.print(f"\n[bold blue][*] Phase 1: Identifying Live Assets on {self.target}...[/bold blue]")
        
        # Try Netdiscover first (Best for Local Networks)
        try:
            # We strip any whitespace to avoid errors
            clean_target = self.target.split()[0] 
            result = subprocess.run(
                ["sudo", "netdiscover", "-r", clean_target, "-PN", "-L"],
                capture_output=True, text=True, timeout=15
            ).stdout
            
            for line in result.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})", line)
                if match:
                    devices.append({"ip": match.group(1), "mac": match.group(2)})
        except Exception:
            pass

        # If netdiscover found nothing or failed, use Nmap Ping Sweep
        if not devices:
            console.print("[yellow][!] Using Nmap Ping Sweep fallback...[/yellow]")
            try:
                scanner.scan(hosts=self.target, arguments="-sn")
                for host in scanner.all_hosts():
                    mac = scanner[host]['addresses'].get('mac', '00:00:00:00:00:00')
                    devices.append({"ip": host, "mac": mac})
            except Exception as e:
                console.print(f"[bold red][!] Discovery Error: {e}[/bold red]")
        
        return devices

    def scan_host(self, device):
        """Phase 2: Port & Service Analysis"""
        ip = device["ip"]
        mac = device["mac"]
        
        args = "-T4"
        if self.fast:
            args += " -F"
        else:
            args += " -sV"
            
        if self.vuln:
            args += " --script vulners"

        try:
            scanner.scan(hosts=ip, arguments=args)
            if ip in scanner.all_hosts():
                host_data = scanner[ip]
                services = []
                vulnerabilities = []
                
                if 'tcp' in host_data:
                    for port, data in host_data['tcp'].items():
                        if data['state'] == 'open':
                            svc_name = data.get('name', 'unknown')
                            svc_ver = data.get('version', '')
                            services.append(f"{port}/{svc_name} [dim]{svc_ver}[/dim]")
                            
                            if 'script' in data:
                                for sid in data['script'].keys():
                                    vulnerabilities.append(f"P{port}: {sid}")

                return {
                    "ip": ip,
                    "mac": mac,
                    "hostname": self.get_hostname(ip),
                    "vendor": self.get_vendor(mac),
                    "services": services,
                    "vulns": vulnerabilities
                }
        except:
            pass
        return None

    def start(self):
        devices = self.run_discovery()
        if not devices:
            console.print("[bold red][-] No active targets found.[/bold red]")
            return

        # Sort devices by IP address for better organization
        try:
            devices.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
        except:
            devices.sort(key=lambda x: x['ip'])

        console.print(f"[bold green][+] Targets Found: {len(devices)}[/bold green]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Reconnaissance in progress...", total=len(devices))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.scan_host, d) for d in devices]
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res:
                        self.results.append(res)
                    progress.update(task, advance=1)

        # Sort final results by IP
        try:
            self.results.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
        except:
            self.results.sort(key=lambda x: x['ip'])

        self.report()

    def report(self):
        table = Table(box=box.SIMPLE_HEAVY, header_style="bold magenta", border_style="blue")
        table.add_column("IP Address", style="bold cyan")
        table.add_column("MAC Address", style="bold yellow")
        table.add_column("Host/Vendor Intel", style="green")
        table.add_column("Services & Versions", style="white")
        
        if self.vuln:
            table.add_column("Security Flaws", style="bold red")

        for r in self.results:
            hostname = r['hostname'] if r['hostname'] else "[dim]---[/dim]"
            vendor = r['vendor'] if r['vendor'] else "[dim]---[/dim]"
            intel = f"[bold]{hostname}[/bold]\n[dim]{vendor}[/dim]"
            
            svcs = "\n".join(r['services']) if r['services'] else "[dim]No open ports[/dim]"
            
            row = [r['ip'], r['mac'], intel, svcs]
            if self.vuln:
                v = "\n".join(r['vulns']) if r['vulns'] else "[green]None[/green]"
                row.append(v)
            
            table.add_row(*row)
            table.add_section()

        console.print("\n", table)
        
        filename = f"scan_{datetime.now().strftime('%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        console.print(f"[bold green][✓] Intelligence archived in {filename}[/bold green]")

if __name__ == "__main__":
    console.print(BANNER_COMPACT)
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target", nargs="?", help="Target IP or Range")
    parser.add_argument("-f", "--fast", action="store_true")
    parser.add_argument("-v", "--vuln", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    
    args = parser.parse_args()
    
    if args.help:
        show_help()
        sys.exit()

    while True:
        target = args.target
        fast = args.fast
        vuln = args.vuln

        # If no target provided via CLI, or we are in subsequent loop iterations
        if not target:
            target_input = console.input("\n[bold yellow]Target (or 'q' to quit, 'h' for help): [/bold yellow]").strip()
            
            if target_input.lower() in ['q', 'quit', 'exit']:
                console.print("[bold red][!] Shutdown signal received. Goodbye![/bold red]")
                break
                
            if target_input.lower() in ['h', 'help', '-h']:
                show_help()
                continue
            
            if not target_input:
                continue
            
            # Handle cases where user types flags in the input
            parts = target_input.split()
            target = parts[0]
            if "-f" in parts or "--fast" in parts: fast = True
            if "-v" in parts or "--vuln" in parts: vuln = True

        if not target:
            break
            
        app = ScanetPro(target, fast, vuln)
        app.start()
        
        # Reset args.target to None so it asks again in the next loop
        args.target = None
