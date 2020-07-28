from scapy.all import srp, Ether, ARP
from typing import List
from dataclasses import dataclass

@dataclass
class ARPResponse:
    ip: str
    mac: str


def arp_ping(interface, ip) -> List[ARPResponse]:
    print(type(ip))
    print(f"module arp: arp pinging {ip} on {interface}")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface)
    responses: List[ARPResponse] = []
    for sent, rcvd in ans:
        print(f"target ip: {rcvd[ARP].psrc}, mac: {rcvd[ARP].hwsrc}")
        responses.append(ARPResponse(rcvd[ARP].psrc, rcvd[ARP].hwsrc))
    return responses
