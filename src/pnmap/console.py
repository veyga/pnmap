import click
import re
import sys
from scapy.all import srp, get_if_list, conf, IP, Ether, ARP, TCP
from pnmap.subnet import *
from typing import List, Optional, Tuple, Union

# result = scan_tcp_port(ip)
# for pkt in result.open:
#     print(f"{pkt[0][0][TCP].dport} is OPEN!")
# for pkt in result.closed:
#     print(f"{pkt[0][0][TCP].dport} is CLOSED!")

# click.echo("All others filtered")
# click.echo(open)
# print(f"{sent[TCP].dport} did not answer (is filtered!)"):



@click.command()
@click.argument("interface")
@click.option("--ip", default="", help="single IP, CIDR, or domain name\n(default=your subnet)")
@click.option("--portrange", nargs=2, default=(0, 80), type=int, help="Range to scan\n(default= --portrange 0 8)")
def main(interface: str, ip: str, portrange: Tuple[int]):
    """ pnmap """
    print("PNMAP WELCOME!")
    valid_interfaces = get_if_list()
    if interface not in valid_interfaces:
        print(f"{interface} not found in your interfaces ({valid_interfaces})")
        sys.exit()

    # default to local subnet 
    localnet = determine_subnet(interface)
    if ip == "":
        ip = str(localnet)

    scan(interface, ip, portrange, localnet)


def scan(interface: str, ip: str, portrange: Tuple[int], localnet: Subnet):
    print(f"Scanning ports {portrange} on host(s) {ip} via interface {interface}")
    targets: List[IP] = []
    if ip == str(localnet) or localnet.contains(ip):
        targets = resolve_local_net(interface, ip, portrange)
    else:
        targets = resolve_external_net(interface, ip, portrange, localnet.gateway)
        # target_ip = ip
        # single_ip = re.search(r"[1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip)
        # if single_ip:
        # cidr = re.search(r"([1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2})", ip)
        # if cidr:
        #     target_ip = cidr.group(1)
        # (interface, _, gateway) = conf.route.route(target_ip)
        # if iface != interface:
        #     print("The interface you provided does not match your default. Using {interface} instead...")
        # if gateway == "0.0.0.0":
        #     targets = resolve_local_net(interface, ip, portrange)
        # else:
        #     targets = resolve_external_net(interface, ip, portrange)


def resolve_local_net(interface: str, ip: str, portrange: Tuple[int]):
    print(f"Target is (in) your subnet! ARP pinging")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface)
    responses = [rcvd for sent, rcvd in ans]
    if not responses:
        print(f"No ARP reply from {ip}, try scanning the whole subnet")
    else:
        targets: List[Ether] = []
        for pkt in responses:
            print(f"mac = {pkt[ARP].hwsrc}    ip = {pkt[ARP].psrc}")
            targets.append(Ether(dst=pkt[ARP].hwsrc) / IP(dst=pkt[ARP].psrc))
        # correct
        # for t in targets:
        #     print(f"target  mac = {t.dst}   ip = {t[IP].dst}")


def resolve_external_net(interface, ip, portrange, gateway):
    print(f"scanning local net:  interface {interface} ip {ip} portrange {portrange}")
    # print("scanning external net")
