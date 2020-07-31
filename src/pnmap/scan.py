from scapy.all import Ether, IP, TCP, ICMP, srp
from typing import List, Tuple, Union
from collections import namedtuple

ScanResult = namedtuple("ScanResult", ["address","l4_protocol","port_statuses"])
PortStatus = namedtuple("PortStatus", ["port_num", "status"])

class Scanner:
    def __init__(self, frames: List[Ether], ports: Union[list, tuple], interface):
        self.frames = frames
        self.ports = ports
        self.interface = interface

    def scan_tcp(self) -> List[ScanResult]:
        tcp_scan_results = []
        for frame in self.frames:
            ans, unans = srp(frame / TCP(flags="S", dport=self.ports), iface=self.interface, timeout=5, verbose=1)
            port_statuses = []
            for sent, received in ans:
                if received.haslayer(TCP):
                    if str(received[TCP].flags) == "SA": #SA = SYN + ACK
                        port_statuses.append(PortStatus(sent[TCP].dport, "open"))
                    elif str(received[TCP].flags) == "RA": #RA = RST + ACK
                        port_statuses.append(PortStatus(sent[TCP].dport, "closed"))
            for sent in unans:
                port_statuses.append(PortStatus(sent[TCP].dport, "filtered"))
            port_statuses.sort()
            tcp_scan_results.append(ScanResult(frame[IP].dst, "TCP", port_statuses))
        return tcp_scan_results

    # def scan_udp(self):
    #     pass

# def scan(frames: List[Ether], ports: Union[list, tuple], interface: str):
#     for frame in frames:
#         # ans, unans = sr(IP(dst="192.168.1.14") / TCP(flags="S", dport=(0, 1024)), timeout=5, verbose=0)
#         ans, unans = srp(frame / TCP(flags="S", dport=(0, 1024)), timeout=5, verbose=0)
#         sr
#     return "success"


# class Scanner:
#     def __init__(self, targets: List[Ether], portrange: Tuple[int,int]):
#         self.targets = targets
#         self.portrange = portrange
# class ScanResult():
#     def __init__(self, open, closed, filtered):
#         self.open = []
#         self.closed = []
#         self.filtered = []

# class TCPScanner:
#     def __init__(self, targets: List[IP], portrange):
#         self.targets = targets
#         self.portrange = portrange

# def scan_tcp_port(ip: str) -> ScanResult:
#     ans, unans = sr(IP(dst=ip) / TCP(flags="S",
#                                      dport=(0, 1024)), timeout=5, verbose=0)

#     rez = ScanResult([], [], [])
#     for sent, received in ans:
#         if received.haslayer(TCP):
#             if str(received[TCP].flags) == "SA":
#                 rez.open.append(ans)
#             elif str(received[TCP].flags) == "RA":
#                 rez.closed.append(ans)
#         elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
#             rez.filtered.append(ans)

#     # Handling unanswered packets
#     rez.filtered.append(unans)
#     # for sent in unans:
#     #     rez.filtered.append(sent)

#     return rez
#     # print("\nAll other ports are filtered.\n")
