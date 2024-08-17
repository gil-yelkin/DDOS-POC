import DDOS
import AntiDoS
from typing import Callable, NoReturn
from Helper import exit_program, on_exception
from scapy.config import conf
from subprocess import CalledProcessError


def detect_DoS_wrapper() -> NoReturn:
    while True:
        try:
            attackers: list[str] = AntiDoS.detect_DoS(conf.ifaces.dev_from_index(input('Please choose an interface to scan:\n'
                                                                                       f'{conf.ifaces}\n'
                                                                                       "(Enter the interface's index)\n"
                                                                                       '> ')))
        except ValueError as e:
            print('Invalid interface index, please try again.\n')
        else:
            break
    num_attackers = len(attackers)
    print(f'{num_attackers} threats found{", all good :)" if num_attackers == 0 else (": " + str(attackers))}')
    for ip in attackers:
        if input(f'Do you wish to block {ip} in your firewall? (Y/N)\n'
                 '> ').upper() == 'Y':
            AntiDoS.block_ip_in_firewall(ip)
            print(f'{ip} Blocked successfully')


commands: dict[Callable] = {0: exit_program,
                            1: DDOS.commit_DoS,
                            2: detect_DoS_wrapper}


def main():
    while True:
        choice: int = -1
        print('What do you wish to do?\n'
              '0: Exit program\n'
              '1: Commit DoS\n'
              '2: Detect potential (D)DoS attacks on your computer')

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
