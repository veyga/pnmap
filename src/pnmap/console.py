from scapy.all import srp, srp1, get_if_list, conf, IP, Ether, ARP, TCP, ICMP
from typing import List, Optional, Tuple, Union
from pnmap.resolve import *
from pnmap.scan import *
from pnmap.subnet import *
from time import time
import pnmap.arp as arp
import click, re, sys, subprocess, functools


def timed(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        start_time = time()
        result = fn(*args, **kwargs)
        end_time = time()
        click.echo(f"\nTime elapsed: {end_time - start_time:.2f}s")
        return result
    return wrapper


INTERFACE_HELP = ''' Target interface\n
                -i wlan0\n
                If only 1 non-loopback interface is available, pnmap will default to that.
            '''
ADDRESS_HELP = ''' Target host\n
                single IP: -a 192.168.1.4\n
                domain name: -a www.google.com\n
                (default = your subnet) [multi-target]
            '''
PORTS_HELP = ''' Target port(s) to scan\n
                  single port: -p 80\n
                  multiple ports: -p 8080 -p 22 -p 58\n
                  (default = [22, 80, 443])
              '''
RANGE_HELP = ''' Target range of ports to scan (inclusive)\n
                  -r 1 1024
              '''
PROTOCOL_HELP = ''' L4 protocol\n
                    tcp: -t TCP\n
                    udp: -t UDP\n
                    (default = BOTH)
               '''

@click.command()
@click.option("--interface", "-i", type=str, help=INTERFACE_HELP)
@click.option("--address","-a", type=str, help=ADDRESS_HELP)
@click.option("--ports","-p", multiple=True, type=click.INT, help=PORTS_HELP)
@click.option("--range","-r", nargs=2, type=click.INT, help=RANGE_HELP)
@click.option("--transport","-t", type=click.Choice(["TCP","UDP","BOTH"], case_sensitive=False),
        default="BOTH", help=PROTOCOL_HELP)
def main(interface: str, address, ports, range, transport):
    """ pnmap - A simple network mapper/port scanner for Linux """
    whoami = subprocess.check_output(["whoami"]).decode("utf-8")
    match = re.search(r"root", whoami)
    if not match:
        click.secho(f"pnmap must be run/installed as root (Scapy requirement)", fg="red")
        sys.exit(1)
    ports = range if range else list(ports) if ports else [22, 80, 443]
    valid_interfaces: list = get_if_list()
    valid_interfaces.remove("lo")

    if not interface and len(valid_interfaces) == 1:
        interface = valid_interfaces[0]
    else:
        while interface not in valid_interfaces:
            interface = click.prompt(click.style(f"Interface not found/ambiguous. Choose from {valid_interfaces}", fg="red"))

    # default to local subnet 
    localnet = determine_subnet(interface)
    if not address:
        address = str(localnet)

    cli = CLI(interface, address, ports, localnet)
    cli.nmap(transport)



class CLI:
    def __init__(self, interface: str, address: str, ports: Union[list,tuple], localnet: Subnet):
        self.interface = interface
        self.address = address
        self.ports = ports
        self.localnet = localnet
        self.results: List[ScanResult] = []


    @timed
    def nmap(self, transport_protocol) -> None:
        p, i, a, l = self.ports, self.interface, self.address, self.localnet
        if isinstance(self.ports, list):
            click.secho(f"pnmap scanning port(s) {p} on host(s) {a} via interface {a}", fg="cyan")
        else:
            click.secho(f"pnmap scanning port(s) {p[0]} to {p[1]} on host(s) {a} via interface {i}", fg="cyan")
        frames: List[Ether] = []
        try:
            if self.address == str(self.localnet) or self.localnet.contains(self.address):
                click.secho(f"Target is (in) your subnet! ARP pinging...", fg="cyan")
                frames = arp.gen_local_frames(i, a, p)
            else:
                click.secho(f"Target is not in your subnet! Routing via gateway {l.gateway}", fg="yellow")
                frames = arp.gen_external_frames(i, a, p, l.gateway)
                ensure_connection(frames[0], self.interface)
        except (arp.ARPError, ConnectionError, IPDomainError) as e:
            click.secho(str(e), fg="red")
            sys.exit(1)

        scanner = Scanner(frames, self.ports, self.interface)
        if transport_protocol == "BOTH":
            click.secho(f"Scanning TCP.....")
            tcp_results = scanner.scan_tcp()
            click.secho(f"Scanning UDP.....")
            udp_results = scanner.scan_udp()
            self.results = scanner.merge_results(tcp_results, udp_results)
        elif transport_protocol == "TCP":
            click.secho(f"Scanning TCP.....")
            self.results = scanner.scan_tcp()
        elif transport_protocol == "UDP":
            click.secho(f"Scanning UDP.....")
            self.results = scanner.scan_udp()

        self._display_results()


    def _display_results(self) -> None:
        for result in self.results:
            click.secho(f"\nAddress: {result.address}", fg="blue")
            # searching through a range --> majority are either filtered or closed, based on firewall
            # so dont display a long list of closed/filtered
            MAX_DISPLAY = 10
            if not isinstance(self.ports, tuple) or (self.ports[1] - self.ports[0] <= MAX_DISPLAY):
                for p in result.port_statuses:
                    if p.status == "open":
                        click.secho(f"{p.port_num}/{p.protocol}\topen", fg="green")
                    elif p.status == "closed":
                        click.secho(f"{p.port_num}/{p.protocol}\tclosed", fg="red")
                    elif p.status == "filtered":
                        click.secho(f"{p.port_num}/{p.protocol}\tfiltered", fg="yellow")
            else:
                num_closed, num_filtered = 0, 0
                for port_status in result.port_statuses:
                    if port_status.status == "closed":
                        num_closed += 1
                    elif port_status.status == "filtered":
                        num_filtered += 1

                for p in result.port_statuses:
                    if p.status == "open":
                        click.secho(f"{p.port_num}/{p.protocol}\topen", fg="green")
                    elif p.status == "closed" and num_closed < MAX_DISPLAY:
                        click.secho(f"{p.port_num}/{p.protocol}\tclosed", fg="red")
                    elif p.status == "filtered" and num_filtered < MAX_DISPLAY:
                        click.secho(f"{p.port_num}/{p.protocol}\tfiltered", fg="yellow")

                if num_closed > MAX_DISPLAY:
                    click.echo(f"Not shown: {num_closed} closed")
                if num_filtered > MAX_DISPLAY:
                    click.echo(f"Not shown: {num_filtered} filtered")


