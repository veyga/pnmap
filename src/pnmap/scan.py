from scapy.all import Ether, IP, TCP, UDP, ICMP, srp
from typing import List, Tuple, Union
from collections import namedtuple

ScanResult = namedtuple("ScanResult", ["address", "port_statuses"])
PortStatus = namedtuple("PortStatus", ["port_num", "status", "protocol"])

class Scanner:
    def __init__(self, frames: List[Ether], ports: Union[list, tuple], interface):
        self.frames = frames
        self.ports = ports
        self.interface = interface

    def scan_tcp(self) -> List[ScanResult]:
        """ Scans this scanner's list of addresses and ports for TCP port statuses """
        tcp_scan_results = []
        for frame in self.frames:
            ans, unans = srp(frame / TCP(flags="S", dport=self.ports), iface=self.interface, timeout=5, verbose=0)
            port_statuses = []
            for sent, received in ans:
                if received.haslayer(TCP):
                    if str(received[TCP].flags) == "SA": #SA = SYN + ACK
                        port_statuses.append(PortStatus(sent[TCP].dport, "open", "TCP"))
                    elif str(received[TCP].flags) == "RA": #RA = RST + ACK
                        port_statuses.append(PortStatus(sent[TCP].dport, "closed", "TCP"))
            for sent in unans:
                port_statuses.append(PortStatus(sent[TCP].dport, "filtered", "TCP"))
            port_statuses.sort()
            tcp_scan_results.append(ScanResult(frame[IP].dst, port_statuses))
        return tcp_scan_results


    def scan_udp(self) -> List[ScanResult]:
        """ Scans this scanner's list of addresses and ports for UDP port statuses """
        udp_scan_results = []
        for frame in self.frames:
            ans, unans = srp(frame / UDP(dport=self.ports), iface=self.interface, timeout=5, verbose=0)
            port_statuses = []
            for sent, received in ans:
                if received.haslayer(ICMP) and int(received[ICMP].type) == 3:
                    # type 3, code 3 --> closed
                    if int(received[ICMP].code) == 3:
                        port_statuses.append(PortStatus(sent[UDP].dport, "closed", "UDP"))
                    # type 3, code 1,2,9,10,13 --> filtered
                    elif int(received[ICMP].code) in [1,2,9,10,13]:
                        port_statuses.append(PortStatus(sent[UDP].dport, "filtered", "UDP"))
                    else:
                        port_statuses.append(PortStatus(sent[UDP].dport, "open", "UDP"))
            for sent in unans:
                port_statuses.append(PortStatus(sent[UDP].dport, "filtered", "UDP"))
            port_statuses.sort()
            udp_scan_results.append(ScanResult(frame[IP].dst, port_statuses))
        return udp_scan_results



    def merge_results(self, tcp_results: List[ScanResult], udp_results: List[ScanResult]):
        """ Merges TCP and UDP scan results for easier display """
        merged_results: List[ScanResult] = []
        for i in range(len(tcp_results)):
            res_for_address: List[PortStatus] = []
            for tport, uport in zip(tcp_results[i].port_statuses, udp_results[i].port_statuses):
                if tport.status == uport.status:
                    res_for_address.append(PortStatus(tport.port_num, tport.status, "TCP/UDP"))
                elif tport.status == "open" and uport.status != "open":
                    res_for_address.append(PortStatus(tport.port_num, "open", "TCP"))
                elif uport.status == "open" and tport.status != "open":
                    res_for_address.append(PortStatus(tport.port_num, "open", "UDP"))
                # closed is generally more useful info than filtered as many IPs have a firewall
                elif tport.status == "closed" and uport.status == "filtered":
                    res_for_address.append(PortStatus(tport.port_num, "closed", "TCP"))
                elif uport.status == "closed" and tport.status == "filtered":
                    res_for_address.append(PortStatus(tport.port_num, "closed", "UDP"))
            merged_results.append(ScanResult(tcp_results[i].address, res_for_address))
        return merged_results
