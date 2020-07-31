from scapy.all import srp, srp1, get_if_list, conf, IP, Ether, ARP, TCP, ICMP
from typing import List, Optional, Tuple, Union
from pnmap.resolve import *
from pnmap.scan import scan
from pnmap.subnet import *
import pnmap.arp as arp
import click
import sys

INTERFACE_HELP = ''' Target interface\n
                If only 1 non-loopback interface is available, pnmap will default to that.
            '''
ADDRESS_HELP = ''' Target host\n
                single IP: -t 192.168.1.4\n
                domain name: -t www.google.com\n
                (default = your subnet) [multi-target]
            '''
PORTS_HELP = ''' Target port(s) to scan\n
                  single port: -p 80\n
                  multiple ports: -p 80 -p 443 -p 22
              '''
RANGE_HELP = ''' Target range of ports to scan\n
                  --r 1 1024
              '''

@click.command()
@click.option("--interface", "-i", type=str, help=INTERFACE_HELP)
@click.option("--address","-a", type=str, help=ADDRESS_HELP)
@click.option("--ports","-p", multiple=True, type=click.INT, help=PORTS_HELP)
@click.option("--range","-r", nargs=2, type=click.INT, help=RANGE_HELP)
def main(interface: str, address, ports, range):
    """ pnmap """
    ports = range if range else list(ports) if ports else [80]
    valid_interfaces: list = get_if_list()
    valid_interfaces.remove("lo")

    if interface:
        while interface not in valid_interfaces:
            interface = click.prompt(click.style(f"{interface} not found. Re-enter from {valid_interfaces}", fg="red"))
    elif len(valid_interfaces) == 1:
        interface = valid_interfaces[0]

    # default to local subnet 
    localnet = determine_subnet(interface)
    if not address:
        address = str(localnet)

    nmap(interface, address, ports, localnet)


def nmap(interface: str, address: str, ports: Union[list, tuple], localnet: Subnet):
    if isinstance(ports, list):
        click.secho(f"pnmap scanning port(s) {ports} on host(s) {address} via interface {interface}", fg="cyan")
    else:
        click.secho(f"pnmap scanning port(s) {ports[0]} to {ports[1]} on host(s) {address} via interface {interface}", fg="cyan")
    frames: List[Ether] = []
    try:
        if address == str(localnet) or localnet.contains(address):
            click.secho(f"Target is (in) your subnet! ARP pinging", fg="cyan")
            frames = arp.gen_local_frames(interface, address, ports)
        else:
            click.secho(f"Target is not in your subnet! Routing via gateway {localnet.gateway}", fg="yellow")
            frames = arp.gen_external_frames(interface, address, ports, localnet.gateway)
            ensure_connection(frames[0], interface)
    except (arp.ARPError, ConnectionError, IPDomainError) as e:
        click.secho(str(e), fg="red")
        sys.exit(1)

    results = scan(frames, ports, interface)
    print(results)


