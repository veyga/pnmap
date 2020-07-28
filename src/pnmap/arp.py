from scapy.all import srp, Ether, ARP
from typing import List
from dataclasses import dataclass

@dataclass
class ARPResponse:
    ip: str
    mac: str


def arp_ping(interface, ip) -> List[ARPResponse]:
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface)
    responses: List[ARPResponse] = []
    for sent, rcvd in ans:
        responses.append(ARPResponse(rcvd[ARP].psrc, rcvd[ARP].hwsrc))
    return responses
