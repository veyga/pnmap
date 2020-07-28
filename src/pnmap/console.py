import click
from pnmap.tcpportscan import *


@click.command()
@click.option("--ip", help="the IP to ping")
def main(ip):
    """ pnmap """
    click.echo("welcome")
    click.echo(f"pinging {ip}")
    result = scan_tcp_port(ip)
    for pkt in result.open:
        print(f"{pkt[0][0][TCP].dport} is OPEN!")
    for pkt in result.closed:
        print(f"{pkt[0][0][TCP].dport} is CLOSED!")

    click.echo("All others filtered")
    # click.echo(open)
    # print(f"{sent[TCP].dport} did not answer (is filtered!)")
