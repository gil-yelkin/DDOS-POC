import subprocess
import re
from scapy.config import Interceptor
from scapy.all import sniff, conf
from scapy.layers.l2 import ARP


class ARPTableEntry:
    def __init__(self, ip_address: str, mac_address: str, entry_type: str, interface: Interceptor = conf.iface):
        self.ip: str = ip_address
        self.mac: str = mac_address
        self.type: str = entry_type
        self.interface: Interceptor = interface

    def __str__(self) -> str:
        # Nice padding for organized printing
        return f"IP: {self.ip:<15} | MAC: {self.mac} | Type: {self.type:<7} | Interface: {self.interface}"


def detect_ARP_spoofing(interface: Interceptor) -> None:
    table: list[ARPTableEntry] = get_ARP_table()

    def packet_handler(packet):
        content = packet[ARP].summary()
        if packet.op == 1:  # Request
            request = content.split('/')[0]
            print(request)
            ips_match = re.compile(r"^.* (\d+\.\d+\.\d+\.\d+).* (\d+\.\d+\.\d+\.\d+)\s*$").match(request)
            print(f'Sender: {ips_match.group(2)} | Requested: {ips_match.group(1)}\n')
        elif packet.op == 2:  # Response
            print(content)
            results = re.compile(r"^.* (([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}).* (\d+\.\d+\.\d+\.\d+)\s*$").match(content)
            print(f'Result: {results.group(1)} | Responder: {results.group(3)}\n')  # 2nd group is trash

    sniff(iface=interface, prn=packet_handler, timeout=120, promisc=True, store=False, filter='arp')
    pass


def get_ARP_table() -> list[ARPTableEntry] | None:
    try:
        table: list[ARPTableEntry] = []
        output = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True).stdout

        # Take the last value in interface row, which is the interface ID in hexa
        interface = conf.ifaces.dev_from_index(int(output.splitlines()[1].split(' ')[-1], 16))  # Convert from hexa to decimal

        for line in output.splitlines()[3:]:  # Skip the first 3 lines
            arp_entry_match = re.compile(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]+)\s+(\w+)\s*$').match(line)
            if arp_entry_match:
                #                   Internet Address (IP)    Physical Address (MAC)    Type (static/dynamic)
                entry = ARPTableEntry(arp_entry_match.group(1), arp_entry_match.group(2), arp_entry_match.group(3), interface)
                table.append(entry)
        return table

    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve ARP table. Error: {e}")
        return None
