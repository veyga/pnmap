from scapy.all import ARP, Ether, IP, srp, srp1
from typing import List, Union
from pnmap.resolve import valid_domain


class ARPError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


def gen_local_frames(interface: str, ip: str, ports: Union[list,tuple]) -> List[Ether]:
    """ Generates local frames. Throws ARPError if no response """
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, iface=interface, verbose=0)
    responses = [rcvd for sent, rcvd in ans]
    if not responses:
        raise ARPError(f"No ARP reply from {ip}, try scanning the whole subnet")
    else:
        return [Ether(dst=pkt[ARP].hwsrc) / IP(dst=pkt[ARP].psrc) for pkt in responses]


@valid_domain
def gen_external_frames(interface: str, ip: str, ports: Union[list, tuple], gateway: str) -> List[Ether]:
    """ Generates external frames. Throws ARPError if gateway is down """
    arp_resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway), timeout=5, iface=interface, verbose=0)
    if not arp_resp:
        raise ARPError(f"Unable to find MAC for gateway IP {gateway}. Is it up?")
    return [Ether(dst=arp_resp[ARP].hwsrc) / IP(dst=ip)]
