import sys
import subprocess
import xml.etree.ElementTree as ET
import os
from rich import print
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import nmap_classes
from rich.console import Console
from rich.progress import Progress, SpinnerColumn
from rich.table import Table
from pyfiglet import Figlet
console = Console()

def print_banner():
    console.print("[bold cyan]Developed by Azhari Ramadhan 🇮🇩[/bold cyan]")

def print_figlet_text():
    f = Figlet(font='big')
    pretty_text = f.renderText('Pretty')
    nmap_text = f.renderText('Nmap')
    console.print("[red]" + pretty_text + "[/red]" + "[white]" + nmap_text + "[/white]")

def print_commands():
    # Buat objek Table
    table = Table(show_header=True, header_style="bold green", caption="Developed By Azhari Ramadhan")

    # Tambahkan kolom ke tabel
    table.add_column("Purpose Command", style="magenta")
    table.add_column("Nmap Commands", style="green")

    # Tambahkan baris ke tabel
    table.add_row("Stealthy Scan", "nmap -sS 10.11.1.X")
    table.add_row("Scan all ports, might take a while.", "nmap -p- 10.11.1.X ")
    table.add_row("Scan for version, with NSE-scripts and trying to identify OS", "nmap -sV -sC -O 10.11.1.X  ")
    table.add_row("All out monsterscan", "nmap -vvv -Pn -A -iL listOfIP.txt ")
    table.add_row("Fast scan", "nmap -F 10.11.1.X  ")
    table.add_row("Only scan the 100 most common ports", "nmap --top-ports 100 10.11.1.X ")
    # Cetak tabel menggunakan objek Console
    console.print(table)

def print_banner():
    console.print("[bold cyan]Developed by Azhari Ramadhan 🇮🇩[/bold cyan]")
def launch_nmap():
    print_banner()
    print_commands()
    print_figlet_text()
    print_banner()
    path = os.path.dirname(os.path.realpath(__file__))
    res_folder = path + "/results/"
    os.makedirs(res_folder, exist_ok=True)
    params = " -oA '" + res_folder + "nmap_scan'"
    nmap_command = input("Please Enter Nmap Command: ")

    # Start the spinner
    with Progress(SpinnerColumn(), "[cyan]{task.description}", transient=True) as progress:
        task = progress.add_task("[cyan]Running Nmap... :fire::fire:🇮🇩", total=100)

        # Run the command and read output in real-time
        process = subprocess.Popen(nmap_command + params, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output_lines = []
        while True:
            output = process.stdout.readline()
            if output == b'' and process.poll() is not None:
                break
            if output:
                # Update the spinner
                progress.update(task, completed=50)
                output_lines.append(output.strip().decode())
        rc = process.poll()

    nmap_output = "\n".join(output_lines)
    nmap_parser(res_folder)
    display_original_nmap(nmap_output)

# ... rest of your code ...

# ... rest of your code ...
def nmap_parser(path):
    target_file = path + "nmap_scan.xml"
    tree = ET.parse(target_file)
    root = tree.getroot()
    host_details = []

    # Get scripts
    for hosts in root.iter('host'):
        host_os = ""
        for addresses in hosts.iter('address'):
            address = addresses.get('addr')
            hostname = address
            break

        for os in hosts.iter('osmatch'):
            host_os = os.get('name')
        host = nmap_classes.Host_Details(hostname, host_os)
        for port in hosts.iter('port'):
            protocol = port.get('protocol')
            portid = port.get('portid')
            for state in port.iter('state'):
                status = state.get('state')  # Correctly indented
            for service in port.iter('service'):
                name = service.get('name')
                product = service.get('product')
                if product is not None and "httpd" in product:
                    product = product.strip("httpd")
                    product = product.strip()
                version = service.get('version')
                extra_info = service.get('extrainfo')
                tunnel = service.get('tunnel')
                host_services = nmap_classes.Scan_Information(protocol, portid, status, name, product, version, extra_info, tunnel)
                for script in port.iter('script'):
                    script_id = script.get('id')
                    script_output = script.get('output')
                    script_information = nmap_classes.Script_Information(script_id, script_output)
                    host_services.script_info.append(script_information)
                host.scan_information.append(host_services)
        host_details.append(host)

    for host in host_details:
        print("\n[green bold]{}: {} {}[/green bold]".format('Target', host.hostname, host.host_os))
        for service in host.scan_information:
            script_signal = 0
            print("\n[cyan]{: <8} {: <8} {: <8} {: <15} {: <15} {: <3}[/cyan]".format("PORT", "STATE", "SERVICE", "VERSION", "EXTRA INFO", "SSL"))

            # Check if variables are None and replace with default value
            port_protocol = (service.port + "/" + service.protocol) if service.port and service.protocol else ""
            state = service.state if service.state else ""
            service_name = service.service if service.service else ""
            product = str(service.product) if service.product else ""
            extra_info = service.extra_info if service.extra_info else ""
            tunnel = service.tunnel if service.tunnel else ""

            print("[green]{: <8} {: <8} {: <8} {: <15} {: <15} {: <3}[/green]".format(port_protocol, state, service_name, product, extra_info, tunnel))

            for script in service.script_info:
                script.script_name = script.script_name.strip()
                output = script.script_output.splitlines()
                while '' in output:
                    output.remove('')
                print("\t[magenta]Script ID: [/magenta]")
                print("{} ".format(script.script_name))
                for line in output:
                    print("\t\t    | {}".format(line.strip()))
                print("\n"),

def custom_redirection(fileobj):
    old = sys.stdout
    sys.stdout = fileobj
    try:
        yield fileobj
    finally:
        sys.stdout = old

def display_original_nmap(nmap_output):
    pass

launch_nmap()
