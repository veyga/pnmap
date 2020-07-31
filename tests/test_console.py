from click.testing import CliRunner
from pnmap.console import main
import pytest


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def interface() -> str:
    return "wlp59s0"


@pytest.fixture
def external_ip() -> str:
    return "45.33.32.156"


def notest_invalid_interface_exits(runner: CliRunner):
    result = runner.invoke(main, ["asdf"])
    assert "not found" in result.output
    assert result.exit_code == 1


def test_no_ip_scans_subnet(runner: CliRunner, interface: str):
    result = runner.invoke(main, ["--interface", interface])
    assert "192.168.1.0/24" in result.output


def test_subnet_ip_scans_single(runner: CliRunner, interface: str):
    result = runner.invoke( main, ["--interface", interface, "--address", "192.168.1.1"])
    assert "Target is (in) your subnet!" in result.output


def test_external_ip_uses_gateway(runner: CliRunner, interface: str, external_ip: str):
    result = runner.invoke(main, ["-i", interface, "--address", external_ip])
    assert "Target is not in your subnet! Routing via gateway" in result.output


def test_no_ports_pings_port_80(runner: CliRunner, interface: str):
    result = runner.invoke(main)
    assert "port(s) [80]" in result.output


def test_single_port_pings_single_port(runner: CliRunner, interface: str):
    result = runner.invoke(main, ["-p", "22"])
    assert "port(s) [22]" in result.output


def test_multiple_ports_pings_multiple_port(runner: CliRunner, interface: str):
    result = runner.invoke(main, ["-p", "22", "-p", "443"])
    assert "port(s) [22, 443]" in result.output


def test_port_range_pings_range(runner: CliRunner, interface: str):
    result = runner.invoke(main, ["-r", "1", "5"])
    assert "port(s) 1 to 5" in result.output
