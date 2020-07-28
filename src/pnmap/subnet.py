from dataclasses import dataclass
from typing import Optional, List
import subprocess
import re


class Subnet:
    def __init__(self, inet, mask):
        self.mask = mask
        self.__host = self._calc_host(inet)
        self.__cidr = self._calc_cidr()

    @property
    def host(self):
        return self.__host

    @property
    def cidr(self):
        return self.__cidr

    def _calc_host(self, ip) -> str:
        ip_oct = ip.split(".")
        mask_oct = self.mask.split(".")
        host_oct: List[str] = []
        print(f"mask oct {mask_oct}")
        print(f"ip oct {ip_oct}")
        for i in range(4):
            host_oct.append(str(int(mask_oct[i]) & int(ip_oct[i])))
        return ".".join(host_oct)

    def _calc_cidr(self) -> str:
        mask_oct = self.mask.split(".")
        total_len = 0
        for oct in self.mask.split("."):
            total_len += len(bin(int(oct))[2:])
        # exclude last 0
        total_len -= 1
        return f"{self.host}/{total_len}"

    def __str__(self):
        return self.cidr



def determine_subnet(interface) -> Optional[Subnet]:
    ifconfig_rez = subprocess.check_output( ["ifconfig", interface]).decode("utf-8")
    match = re.search( r"(inet) ([1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", ifconfig_rez)
    if not match:
        return None
    inet = match.group(2)
    match = re.search( r"(netmask) ([1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", ifconfig_rez)
    if not match:
        return None
    mask = match.group(2)
    return Subnet(inet, mask)
