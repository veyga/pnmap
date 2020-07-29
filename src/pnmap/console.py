from scapy.all import srp, srp1, get_if_list, conf, IP, Ether, ARP, TCP, ICMP
from pnmap.subnet import Subnet, determine_subnet
from pnmap.scan import Scanner
from typing import List, Optional, Tuple, Union
import click
import logging
import sys

# Suppress all logging less than error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


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
        # click.Context().exit(1)

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
    if ip == str(localnet) or localnet.contains(ip):
        frames = resolve_local_net(interface, ip, ports)
    else:
        frames = resolve_external_net(interface, ip, ports, localnet.gateway)
    for frame in frames:
        click.secho(f"gonna do a port scan on ip {frame[IP].dst}", fg="green")


def resolve_local_net(interface: str, ip: str, ports: Union[list,tuple]) -> List[Ether]:
    click.secho(f"Target is (in) your subnet! ARP pinging", fg="cyan")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface)
    responses = [rcvd for sent, rcvd in ans]
    if not responses:
        click.secho(f"No ARP reply from {ip}, try scanning the whole subnet", fg="red")
        sys.exit(1)
    else:
        return [Ether(dst=pkt[ARP].hwsrc) / IP(dst=pkt[ARP].psrc) for pkt in responses]


def resolve_external_net(interface, ip, ports, gateway) -> List[Ether]:
    click.secho(f"Target is not in your subnet! Routing via gateway {gateway}", fg="yellow")
    arp_resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway), timeout=5, iface=interface, verbose=0)
    if not arp_resp:
        click.secho(f"Unable to find MAC for gateway IP {gateway}. Is it up?", fg="red")
        sys.exit(1)
    mac = arp_resp[ARP].hwsrc
    click.secho(f"Pinging {ip}...", fg="cyan")
    ans, unans = srp(Ether(dst=mac) / IP(dst=ip) / ICMP(), timeout = 5, iface=interface, verbose=1)
    if not ans:
        click.secho(f"{ip} unreachable. exiting....", fg="red")
        sys.exit(1)
    return [Ether(dst=mac) / IP(dst=ip)]
