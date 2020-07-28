import click
import re
from pnmap.subnet import *
import pnmap.arp
import sys
from scapy.all import get_if_list, conf
from typing import List, Optional, Tuple, Union

# result = scan_tcp_port(ip)
# for pkt in result.open:
#     print(f"{pkt[0][0][TCP].dport} is OPEN!")
# for pkt in result.closed:
#     print(f"{pkt[0][0][TCP].dport} is CLOSED!")

# click.echo("All others filtered")
# click.echo(open)
# print(f"{sent[TCP].dport} did not answer (is filtered!)")




@click.command()
@click.argument("iface")
@click.option("--ip", default="", help="single IP, CIDR, or domain name\n(default=your subnet)")
@click.option("--portrange", nargs=2, default=(0, 80), type=int, help="Range to scan\n(default= --portrange 0 8)")
def main(iface: str, ip: str, portrange: Tuple[int]):
    """ pnmap """
    valid_interfaces = get_if_list()
    if iface not in valid_interfaces:
        print(f"{iface} not found in your interfaces ({valid_interfaces})")
        sys.exit()

    # default to local subnet 
    target: Union[str, Subnet]
    if ip == "":
        subnet = pnmap.subnet.determine_subnet(iface)
        if not subnet:
            print("No IP provided; and subnet cannot be determined. Please provide explicit IP")
            sys.exit()
        else:
            target = subnet
    else:
        target = ip

    scan(iface, target, portrange)


def scan(iface: str, ip: Union[str, Subnet], portrange: Tuple[int]):
    if isinstance(ip, Subnet):
        scan_local_net(iface, str(ip), portrange)
        return
    target_ip = ip
    cidr = re.search(r"([1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2})", ip)
    if cidr:
        target_ip = cidr.group(1)
    (interface, _, gateway) = conf.route.route(target_ip)
    # print(f"interface: {interface}, outgoing_ip {outgoing_ip}, gateway: {gateway}, target: {target_ip}")
    if iface != interface:
        print("The interface you provided does not match your default. Using {interface} instead...")
    if gateway == "0.0.0.0":
        scan_local_net(interface, ip, portrange)
    else:
        scan_external_net(interface, ip, portrange)

def scan_local_net(iface: str, ip: str, portrange: Tuple[int]):
    # print(f"scanning local net:  iface {iface} ip {ip} portrange {portrange}")
    # if isinstance(ip, Subnet):
    #     ip = str(subnet)
    #     print(f"scanning whole subnet {ip}")
    # else:
    #     print("scanning subnet target: {ip}")
    print(f"scanning local net {ip}")
    print(f"arp pinging {ip} on {iface}")
    responses = pnmap.arp.arp_ping(iface, str(ip))
    print(f"arp results: {responses}")


def scan_external_net(interface, ip, portrange):
    print(f"scanning local net:  iface {iface} ip {ip} portrange {portrange}")
    # print("scanning external net")
