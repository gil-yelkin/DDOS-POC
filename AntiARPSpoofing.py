from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass
from idlelib.autocomplete import TRY_A

from scapy.config import Interceptor
from scapy.all import sniff, conf
from scapy.layers.l2 import ARP


@dataclass(slots=True)
class ARPTableEntry:
    ip: str
    mac: str
    type: str
    interface: Interceptor

    def __str__(self) -> str:
        # Nice padding for organized printing
        return f"IP: {self.ip:<15} | MAC: {self.mac} | Type: {self.type:<7} | Interface: {self.interface}"

@dataclass(frozen=True, slots=True)
class ARPRequest:
    requested_ip: str
    sender_ip: str

    # Change eq method for convenience
    def __eq__(self, other_sender_ip: str) -> bool:
        return self.sender_ip == other_sender_ip

@dataclass(frozen=True, slots=True)
class ARPResponse:
    responder_ip: str
    response_mac: str

def detect_ARP_spoofing(interface: Interceptor) -> None:
    table: list[ARPTableEntry] = get_ARP_table()
    [print(x) for x in table]
    print()
    requests: list[ARPRequest] = []

    def packet_handler(packet):
        content = packet[ARP].summary().split('/')[0]  # Scapy shit
        if packet.op == 1:  # Request
            ips_match = re.compile(r"^.* (\d+\.\d+\.\d+\.\d+).* (\d+\.\d+\.\d+\.\d+)\s*$").match(content)
            request = ARPRequest(*ips_match.groups())  # Unpack groups
            requests.append(request)
            print(request)
        elif packet.op == 2:  # Response
            results = re.compile(r"^.* (([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}).* (\d+\.\d+\.\d+\.\d+)\s*$").match(content)
            # Discard 2nd group because of regex syntax
            response = ARPResponse(results.group(3), results.group(1))
            request = requests.pop(requests.index(packet.pdst))  # find dest
            print(f"{response} | {request}")
            # Need to validate in that response.response_mac is
            # same as the MAC of request.requested_ip in my table
            print([x for x in table if x.ip == request.requested_ip])  # Doesn't work??


    sniff(iface=interface, prn=packet_handler, timeout=120, promisc=True, store=False, filter='arp')
    pass


def get_ARP_table() -> list[ARPTableEntry] | None:
    try:
        table: list[ARPTableEntry] = []
        output = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True).stdout
        for line in output.splitlines():
            interface: Interceptor
            if line.startswith('Interface:'):
                # Take the last value in interface row, which is the interface ID in hex
                interface = conf.ifaces.dev_from_index(int(line.split(' ')[-1], 16))  # Convert from hex to decimal
            arp_entry_match = re.compile(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]+)\s+(\w+)\s*$').match(line)
            if arp_entry_match:
                #                     Internet Address (IP)     Physical Address (MAC)    Type (static/dynamic)
                entry = ARPTableEntry(arp_entry_match.group(1), arp_entry_match.group(2), arp_entry_match.group(3), interface)
                table.append(entry)
        return table

    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve ARP table. Error: {e}")
        return None


def main():
    for entry in get_ARP_table():
        print(entry)


if __name__ == '__main__':
    main()
