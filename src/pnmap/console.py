from scapy.all import srp, srp1, get_if_list, conf, IP, Ether, ARP, TCP, ICMP
from typing import List, Optional, Tuple, Union
from pnmap.resolve import *
from pnmap.scan import scan
from pnmap.subnet import *
import pnmap.arp as arp
import click
import sys

IP_HELP = ''' Target host\n
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
@click.argument("interface", nargs=1)
@click.option("--ip","-i", type=str, help=IP_HELP)
@click.option("--ports","-p", multiple=True, type=click.INT, help=PORTS_HELP)
@click.option("--range","-r", nargs=2, type=click.INT, help=RANGE_HELP)
def main(interface: str, ip, ports, range):
    """ pnmap """
    ports = range if range else list(ports) if ports else [80]
    valid_interfaces = get_if_list()
    if interface not in valid_interfaces:
        click.secho(f"{interface} not found in your interfaces ({valid_interfaces})", fg="red")
        sys.exit(1)

    # default to local subnet 
    localnet = determine_subnet(interface)
    if not ip:
        ip = str(localnet)

    nmap(interface, ip, ports, localnet)


def nmap(interface: str, ip: str, ports: Union[list, tuple], localnet: Subnet):
    if isinstance(ports, list):
        click.secho(f"pnmcallbackap scanning port(s) {ports} on host(s) {ip} via interface {interface}", fg="cyan")
    else:
        click.secho(f"pnmap scanning port(s) {ports[0]} to {ports[1]} on host(s) {ip} via interface {interface}", fg="cyan")
    frames: List[Ether] = []
    try:
        if ip == str(localnet) or localnet.contains(ip):
            click.secho(f"Target is (in) your subnet! ARP pinging", fg="cyan")
            frames = arp.gen_local_frames(interface, ip, ports)
        else:
            click.secho(f"Target is not in your subnet! Routing via gateway {localnet.gateway}", fg="yellow")
            frames = arp.gen_external_frames(interface, ip, ports, localnet.gateway)
            ensure_connection(frames[0], interface)
    except (arp.ARPError, ConnectionError, IPDomainError) as e:
        click.secho(str(e), fg="red")
        sys.exit(1)

    results = scan(frames, ports, interface)
    print(results)


