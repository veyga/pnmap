from dataclasses import dataclass
from typing import Optional, List
from pnmap.constants import IPV4r, CIDRr
import subprocess, re

@dataclass
class CIDR:
    host: str
    suffix: int

    def __str__(self):
        return f"{self.host}/{self.suffix}"


class Subnet:
    def __init__(self, inet, mask):
        self.mask = mask
        self.__cidr = self._calc_cidr(inet)
        self.__gateway = self._calc_gateway()

    @property
    def cidr(self) -> CIDR:
        return self.__cidr

    @property
    def gateway(self) -> str:
        return self.__gateway

    def _calc_cidr(self, ip) -> CIDR:
        # calculate host address
        ip_oct = ip.split(".")
        mask_oct = self.mask.split(".")
        host_oct: List[str] = []
        for i in range(4):
            host_oct.append(str(int(mask_oct[i]) & int(ip_oct[i])))
        host = ".".join(host_oct)
        # calculate suffix
        total_len = 0
        for oct in self.mask.split("."):
            total_len += len(bin(int(oct))[2:])
        total_len -= 1  # exclude last 0
        return CIDR(host, total_len)

    def _calc_gateway(self) -> str:
        host_octets = self.cidr.host.split(".")
        target_oct = self.cidr.suffix // 8
        gateway_octets = []
        for i in range(4):
            if i != target_oct:
                gateway_octets.append(host_octets[i])
            else:
                gateway_octets.append(str(int(host_octets[i]) + 1))
        return ".".join(gateway_octets)


    def contains(self, ip: str) -> bool:
        """ determines in a given IP falls with a subnet """
        match = re.search(rf"{IPV4r}\Z", ip)
        if not match:
            return False
        return self == Subnet(match.group(0), self.mask)

    def __eq__(self, other):
        return str(self) == str(other)

    def __str__(self):
        return str(self.cidr)


def determine_subnet(interface: str) -> Subnet:
    """ detemines the subnet of a given interface """
    ifconfig_rez = subprocess.check_output(["ifconfig", interface]).decode("utf-8")
    inet, mask = ("0.0.0.0", "255.255.255.255")
    match = re.search(rf"inet ({IPV4r})", ifconfig_rez)
    if match:
        inet = match.group(1)
    match = re.search(rf"netmask ({IPV4r})", ifconfig_rez)
    if match:
        mask = match.group(1)
    return Subnet(inet, mask)
