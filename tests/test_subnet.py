from pnmap.subnet import Subnet, CIDR, determine_subnet
import pytest

def test_ifconfig_results_in_correct_subnet():
    assert determine_subnet("wlp59s0").cidr == CIDR("192.168.1.0", 24)

@pytest.mark.parametrize("host, mask, expected", [
        ("192.168.1.14", "255.255.255.0", CIDR("192.168.1.0", 24)),
        ("192.168.45.55", "255.255.248.0", CIDR("192.168.40.0", 21)),
        # ("192.168.45.55", "255.255.255.192", CIDR("192.168.45.0", 26)),
    ]
)
def test_from_host_parameterized(host, mask, expected):
    assert Subnet.from_host(host, mask).cidr == expected
