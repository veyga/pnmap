from scapy.all import srp, srp1, get_if_list, conf, IP, Ether, ARP, TCP, ICMP
from pnmap.subnet import Subnet, determine_subnet
from pnmap.scan import Scanner
from typing import List, Optional, Tuple, Union
import click
import sys
import logging

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
        print(f"{interface} not found in your interfaces ({valid_interfaces})")
        sys.exit()

    # default to local subnet 
    localnet = determine_subnet(interface)
    if not ip:
        ip = str(localnet)

    nmap(interface, ip, ports, localnet)


def nmap(interface: str, ip: str, ports: Union[list, tuple], localnet: Subnet):
    if isinstance(ports, list):
        print(f"pnmap scanning ports {ports} on host(s) {ip} via interface {interface}")
    else:
        print(f"pnmap scanning ports {ports[0]} to {ports[1]} on host(s) {ip} via interface {interface}")
    frames: List[Ether] = []
    if ip == str(localnet) or localnet.contains(ip):
        frames = resolve_local_net(interface, ip, ports)
    else:
        frames = resolve_external_net(interface, ip, ports, localnet.gateway)
    for frame in frames:
        print(f"gonna do a port scan on ip {frame[IP].dst}")


def resolve_local_net(interface: str, ip: str, ports: Union[list,tuple]) -> List[Ether]:
    print(f"Target is (in) your subnet! ARP pinging")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface)
    responses = [rcvd for sent, rcvd in ans]
    if not responses:
        print(f"No ARP reply from {ip}, try scanning the whole subnet")
        sys.exit()
    else:
        frames: List[Ether] = []
        for pkt in responses:
            frames.append(Ether(dst=pkt[ARP].hwsrc) / IP(dst=pkt[ARP].psrc))
        return frames


def resolve_external_net(interface, ip, ports, gateway) -> List[Ether]:
    print(f"Target is not in your subnet! Routing via gateway {gateway}")
    arp_resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway), timeout=5, iface=interface, verbose=0)
    if not arp_resp:
        print(f"Unable to find MAC for gateway IP {gateway}. Is it up?")
        sys.exit()
    mac = arp_resp[ARP].hwsrc
    print(f"Pinging {ip}...")
    ans, unans = srp(Ether(dst=mac) / IP(dst=ip) / ICMP(), timeout = 5, iface=interface, verbose=1)
    if not ans:
        print(f"{ip} unreachable. exiting....")
        sys.exit()
    return [Ether(dst=mac) / IP(dst=ip)]
