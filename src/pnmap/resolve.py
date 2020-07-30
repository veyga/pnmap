from functools import wraps
from typing import Union, List
from scapy.all import DNS, DNSQR, DNSRRSOA, Ether, ICMP, IP, UDP, sr1, srp
import re

IPV4r: str = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
# CIDRr: str = IPV4r + "\/[0-9]{1,2}"

class IPDomainError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class ConnectionError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


def is_ipv4_address(ip: str):
    """ determines if an IP string is an IPv4 address """
    return re.search(rf"{IPV4r}\Z", ip)


def valid_domain(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        address = args[1]
        if not is_ipv4_address(address):
            print(f"{address} not valid apparently. DNSing {address}")
            dns_resp = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname=address)))
            if dns_resp.haslayer(DNSRRSOA):
                raise IPDomainError(f"{address} could not be resolved via DNS or is not in IPv4 format")
        return fn(*args, **kwargs)
    return wrapper


def ensure_connection(frame: Ether, interface: str):
    """ pings target ip. raises ConnectionError if no response """
    ans, unans = srp(frame / ICMP(), timeout = 5, iface=interface, verbose=1)
    if not ans:
        raise ConnectionError("Destination unreachable...")
    return None



# def ensure_connection(fn):
#     @wraps(fn)
#     def wrapper(*args, **kwargs):
#         for frame in args[0]:
#             ans, unans = srp(frame / ICMP(), timeout = 5, iface=args[2], verbose=1)
#             if not ans:
#                 raise ConnectionError("Destination did not respond. Try a different one")
#             raise ValueError
#         return fn(*args, **kwargs)
#     return wrapper

# def generate_frames(interface: str, ip: str, ports: Union[list, tuple], ) -> List[Ether]:
#     pass

