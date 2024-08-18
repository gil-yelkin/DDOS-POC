import subprocess
import re
from scapy.config import Interceptor
from scapy.all import conf


class ARPTableEntry:
    def __init__(self, ip_address: str, mac_address: str, entry_type: str, interface: Interceptor = conf.iface):
        """
        Initialize an ARP table entry.

        :param ip_address: IP address associated with the entry (str).
        :param mac_address: MAC address associated with the entry (str).
        :param interface: Network interface associated with the entry (str).
        """
        self.ip: str = ip_address
        self.mac: str = mac_address
        self.type: str = entry_type
        self.interface: Interceptor = interface

    def __str__(self):
        """
        Return a string representation of the ARP table entry.
        """
        return f"IP: {self.ip}, MAC: {self.mac}, Type: {self.type}, Interface: {self.interface}"


def detect_ARP_spoofing() -> None:
    pass


def get_ARP_table() -> list[ARPTableEntry]:
    try:
        table: list[ARPTableEntry] = []
        output = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True).stdout
        interface = conf.ifaces.dev_from_index(int(output.splitlines()[1].split(' ')[-1], 16))
        for line in output.splitlines()[3::]:
            arp_entry_match = re.compile(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]+)\s+(\w+)\s*$').match(line)
            if arp_entry_match:
                x = ARPTableEntry(arp_entry_match.group(1), arp_entry_match.group(2), arp_entry_match.group(3), interface)
                table.append(x)

        return table
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve ARP table. Error: {e}")
        return None
