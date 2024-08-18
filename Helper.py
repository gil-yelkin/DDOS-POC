import re
from scapy.config import conf
from scapy.config import Interceptor

IP_REGEX_PATTERN_STRING: str = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                               r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                               r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                               r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
IP_REGEX_MATCHER: re.Pattern = re.compile(IP_REGEX_PATTERN_STRING)


def is_local(ip: str) -> bool:
    ip_bytes = ip.split('.')
    return ip_bytes[0] == '10' or ip_bytes[0:1] == ['192.168'] or (ip_bytes[0] == '172' and 16 <= ip_bytes[1] <= 31)


def get_ip_type(ip: str) -> str:
    return "local" if is_local(ip) else "remote"


def get_ip_from_user() -> str:
    ip = input("Enter an ip address to DoS: \n"
               "> ")

    while IP_REGEX_MATCHER.match(ip) is None:
        ip = input("Invalid IP address, please try again: \n"
                   "> ")

    return ip


def get_interface_from_user() -> Interceptor:
    network_interface = input('Please choose an interface to scan:\n'
                              f'{conf.ifaces}\n'
                              "(Enter the interface's index)\n"
                              '> ')
    return conf.ifaces.dev_from_index(network_interface)


def exit_program() -> None:
    print('Goodbye!')
    exit(0)


def on_exception(e: BaseException) -> None:
    print(f'An error occurred:\n{e}\n')
