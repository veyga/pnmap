import click
import re
import pnmap.subnet
import pnmap.arp
from scapy.all import *
from typing import List, Optional, Tuple

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

    if ip == "":
        ip = pnmap.subnet.determine_subnet(iface)
        if not ip:
            print("No IP provided; and subnet cannot be determined. Please provide explicit IP")
            sys.exit()

    scan(iface, ip, portrange)


def scan(iface, ip, portrange):
    print(f"scanning {args}")
    (interface, outgoing_ip, gateway) = conf.route.route(ip)
    if iface != interface:
        print("The interface you provided does not match your default. Using {interface} instead...")
    print(gateway)
    if gateway == "0.0.0.0":
        print("doing arp_ping")
        responses = pnmap.arp.arp_ping(interface, outgoing_ip)
        print(f"arp results: {responses}")


