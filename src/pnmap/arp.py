from scapy.all import srp, Ether, ARP, IP
from typing import List
from dataclasses import dataclass

# @dataclass
# class ARPResponse:
#     ip: str
#     mac: str


class AddressResolutionProtocol:
    @staticmethod
    def ping(interface, ip) -> List[Ether]:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface)
        responses: List[Ether] = []
        for sent, rcvd in ans:
            responses.append(rcvd)
            # responses.append(ARPResponse(rcvd[ARP].psrc, rcvd[ARP].hwsrc))
        return responses


def do_it():
    pass
