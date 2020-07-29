#!/usr/bin/env python

from scapy.all import IP, TCP, ICMP, sr
from typing import List
import logging

# This will suppress all messages that have a lower level of seriousness than error messages.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# class TCPScanner:
#     for target in targets:
#         print("scanning sup")

class ScanResult():
    def __init__(self, open, closed, filtered):
        self.open = []
        self.closed = []
        self.filtered = []

class TCPScanner:
    def __init__(self, targets: List[IP], portrange):
        self.targets = targets
        self.portrange = portrange

def scan_tcp_port(ip: str) -> ScanResult:
    ans, unans = sr(IP(dst=ip) / TCP(flags="S",
                                     dport=(0, 1024)), timeout=5, verbose=0)

    rez = ScanResult([], [], [])
    for sent, received in ans:
        if received.haslayer(TCP):
            if str(received[TCP].flags) == "SA":
                rez.open.append(ans)
            elif str(received[TCP].flags) == "RA":
                rez.closed.append(ans)
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            rez.filtered.append(ans)

    # Handling unanswered packets
    rez.filtered.append(unans)
    # for sent in unans:
    #     rez.filtered.append(sent)

    return rez
    # print("\nAll other ports are filtered.\n")
