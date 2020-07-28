import click
import re
import pnmap.subnet
from scapy.all import *
from scapy.plist import SndRcvList
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
        subnet = pnmap.subnet.determine_subnet(iface)
        if not subnet:
            print("No IP provided; and subnet cannot be determined. Please provide explicit IP")
        print(f"your subnet is {subnet}")
        print(type(portrange))
        # print(f"subnet host {subnet.host}")
        # print(f"subnet mask {subnet.mask}")
        # print(f"subnet cidr {subnet.cidr}")



def scan(ip, iface, portrange):
    print(f"scanning {args}")
    (interface, outgoing_ip, gateway) = conf.route.route(args.ip)
    print(gateway)
    if gateway == "0.0.0.0":
        print("doing arp_ping")
        responses = arp_ping(interface, outgoing_ip)
        print(f"arp results: {responses}")


