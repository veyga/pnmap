from scapy.all import Ether, IP, TCP, ICMP, sr
from typing import List, Tuple, Union

# class TCPScanner:
#     for target in targets:
#         print("scanning sup")

def scan(frames: List[Ether], ports: Union[list, tuple], interface: str):
    return "success"
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
