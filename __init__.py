import DDOS
import AntiDoS
import AntiARPSpoofing
from typing import Callable, NoReturn
from Helper import exit_program, on_exception, get_interface_from_user
from subprocess import CalledProcessError


def detect_DoS_wrapper() -> NoReturn:
    attackers: list[str] = AntiDoS.detect_DoS(get_interface_from_user())
    num_attackers = len(attackers)
    print(f'{num_attackers} threats found{", all good :)" if num_attackers == 0 else (": " + str(attackers))}')
    for ip in attackers:
        if input(f'Do you wish to block {ip} in your firewall? (Y/N)\n'
                 '> ').upper() == 'Y':
            AntiDoS.block_ip_in_firewall(ip)
            print(f'{ip} Blocked successfully')
        else:
            print('Threat overlooked.')


def detect_ARP_wrapper() -> NoReturn:
    AntiARPSpoofing.detect_ARP_spoofing(get_interface_from_user())


commands: dict[Callable] = {0: exit_program,
                            1: DDOS.commit_DoS,
                            2: detect_DoS_wrapper,
                            3: detect_ARP_wrapper}


def main():
    while True:
        choice: int = -1
        print('What do you wish to do?\n'
              '0: Exit program\n'
              '1: Commit DoS\n'
              '2: Detect potential (D)DoS attacks on your computer\n'
              '3: Detect potential ARP Spoofing attacks on your network')

        while choice not in commands.keys():
            try:
                choice = int(input('> '))
            except ValueError:
                print('Unavailable command, please try again.')
        try:
            commands[choice]()
        except OSError as e:
            on_exception(e)
            print('Incompatible Npcap version, please update Npcap.')
        except CalledProcessError as e:
            on_exception(e)
            print('Insufficient permissions, rerun program as administrator.')


if __name__ == "__main__":
    main()
