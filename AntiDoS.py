from scapy.all import sniff, get_if_addr, conf
from scapy.layers.inet import IP
from scapy.config import Interceptor
from collections import deque
import time
import subprocess
import sys
from Helper import get_ip_type

MAX_HISTORY: int = 256
THRESHOLD: int = 64


def block_ip_in_firewall(ip: str) -> None:
    # for Windows OS
    def block_ip_in_firewall_windows() -> None:
        nonlocal ip
        command = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                   f'name="BlockIP_{ip}"',
                   'dir=in',
                   'action=block',
                   f'{get_ip_type(ip)}ip="{ip}"']
        subprocess.run(command, check=True)

    # for Linux OS
    def block_ip_in_firewall_linux() -> None:
        nonlocal ip
        raise NotImplementedError

    if sys.platform.startswith('linux'):
        block_ip_in_firewall_linux(ip)
    elif sys.platform == "win32":
        block_ip_in_firewall_windows(ip)
    else:
        print(f'the "{sys.platform}" OS is not yet supported.')
        raise NotImplementedError


def detect_DoS(interface: Interceptor) -> list[str]:
    my_ip = get_if_addr(interface)
    attackers: list[str] = list()
    packets = deque(maxlen=MAX_HISTORY)  # Fixed-size queue for efficient packet handling

    def packet_handler(packet):
        nonlocal attackers, packets, my_ip
        if IP not in packet:
            # print(f"Skipped {packet}")
            return

        src_ip = packet[IP].src
        if src_ip == my_ip:
            return

        # print(packet)
        packets.append((time.time(), src_ip))

        # Count packets from the same source in the last n seconds
        packet_count = sum(1 for ts, ip in packets if ip == src_ip and ts >
                           time.time() - 30)
        if src_ip not in attackers and packet_count > THRESHOLD:
            attackers.append(src_ip)
            print(f"Potential DoS attack from {src_ip}")

    print('Scanning incoming traffic for malicious activity...')
    sniff(iface=interface, prn=packet_handler, timeout=30, promisc=False, store=False)
    return attackers


def main():
    print(f"Started sniffing on host {get_if_addr(conf.iface)}...\n")
    try:
        detect_DoS(conf.iface)
    except KeyboardInterrupt:
        print("\nSniffing stopped.")


if __name__ == "__main__":
    print("running")
    main()
