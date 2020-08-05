from dataclasses import dataclass
from typing import List
from pnmap.resolve import *
import subprocess, re

@dataclass
class CIDR:
    netid: str
    suffix: int

    def __str__(self):
        return f"{self.netid}/{self.suffix}"


class Subnet:
    def __init__(self, netid, mask):
        self.netid = netid
        self.mask = mask
        self.cidr = self._calc_cidr()
        self.gateway = self._calc_gateway()

    @staticmethod
    def from_host(ip, mask):
        ip_oct = ip.split(".")
        mask_oct = mask.split(".")
        net_oct: List[str] = []
        for i in range(4):
            net_oct.append(str(int(mask_oct[i]) & int(ip_oct[i])))
        netid = ".".join(net_oct)
        return Subnet(netid, mask)


    def _calc_cidr(self) -> CIDR:
        total_len = 0
        for oct in self.mask.split("."):
            total_len += bin(int(oct)).count("1")
        return CIDR(self.netid, total_len)


    def _calc_gateway(self) -> str:
        route = subprocess.check_output(["route", "-n"]).decode("utf-8")
        match = re.search(rf"0\.0\.0\.0\s*({IPV4r})", route)
        if match:
            return match.group(1)
        else:
            return "0.0.0.0"


    def contains(self, ip: str) -> bool:
        """ determines in a given IP falls with a subnet """
        match = is_ipv4_address(ip)
        if not match:
            return False
        return self == Subnet.from_host(ip, self.mask)

    def __eq__(self, other):
        return str(self) == str(other)

    def __str__(self):
        return str(self.cidr)


def determine_subnet(interface: str) -> Subnet:
    """ detemines the subnet of a given interface """
    ifconfig_rez = subprocess.check_output(["sudo", "ifconfig", interface]).decode("utf-8")
    inet, mask = ("0.0.0.0", "255.255.255.255")
    match = re.search(rf"inet ({IPV4r})", ifconfig_rez)
    if match:
        inet = match.group(1)
    match = re.search(rf"netmask ({IPV4r})", ifconfig_rez)
    if match:
        mask = match.group(1)
    return Subnet.from_host(inet, mask)
