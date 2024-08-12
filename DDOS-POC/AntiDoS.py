from scapy.all import sniff, get_if_addr, conf
from scapy.layers.inet import IP
from collections import deque
import time
from sys import stdout
import subprocess

MY_IP = get_if_addr(conf.iface)
MAX_HISTORY = 5

def block_ip_in_firewall(ip: str) -> None:
    # for Windows OS
    def block_ip_in_firewall_windows(ip: str) -> None:
        command = [ 'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=BlockDoSIP_{ip_address}',
                    f'dir=in',
                    f'action=block',
                    f'remoteip={ip_address}' ]
        subprocess.run(command, check=True)
        
    # for Linux OS
    def block_ip_in_firewall_linux(ip: str) -> None:
        raise NotImplementedError
        
    if sys.platform.startswith('linux'):
        block_ip_in_firewall_linux(ip)
    elif sys.platform == "win32":
        block_ip_in_firewall_windows(ip)
    else:
        print(f'the "{sys.platform}" OS is not yet supported.')
        raise NotImplementedError

def dos_detector(interface) -> list[str]:
    attackers: list[str] = []
    packets = deque(maxlen=MAX_HISTORY)  # Fixed-size queue for efficient packet handling
    threshold = 3

    def packet_handler(packet):
        nonlocal attackers, packets, threshold
        if IP not in packet:
            # print(f"Skipped {packet}")
            return

        src_ip = packet[IP].src
        if src_ip == MY_IP:
            return

        print(packet)
        packets.append((time.time(), src_ip))
        print(packets)

        # Count packets from the same source in the last n seconds
        packet_count = sum(1 for ts, ip in packets if ip == src_ip and ts >
                           time.time() - 30)
        if packet_count > threshold:
            attackers.append(src_ip)
            print(f"Potential DoS attack from {src_ip}")

    sniff(iface=interface, prn=packet_handler)
    return attackers


def main():
    print(f"Started sniffing on host {MY_IP}...\n")
    try:
        dos_detector(conf.iface)
    except KeyboardInterrupt:
        print("\nSniffing stopped.")


if __name__ == "__main__":
    print("running")
    main()
