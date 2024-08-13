import DDOS
import AntiDoS
from typing import Callable, NoReturn


def detect_DoS_wrapper() -> NoReturn:
    print('Scanning incoming traffic for malicious activity...')
    attackers: list[str] = AntiDoS.detect_DoS()
    num_attackers = len(attackers)
    print(f'{num_attackers} threats found{", all good :)" if num_attackers == 0 else (": " + str(attackers))}')
    for ip in attackers:
        if input(f'Do you wish to block {ip} in your firewall?') == '0':
            AntiDoS.block_ip_in_firewall(ip)


commands: dict[Callable] = {0: DDOS.commit_DoS,
                            1: detect_DoS_wrapper}


def main():
    while True:
        choice: int = int(input('What do you wish to do?\n'
                                '0: Commit DoS\n'
                                '1: Detect potential (D)DoS attacks on your computer\n'
                                '> '))

        while choice not in commands.keys():
            choice = int(input('Unavailable command, please try again.\n'
                               '> '))
        try:
            commands[choice]()
        except BaseException as e:
            print(f'An error occurred:\n{e}')
        except OSError:
            print('Insufficient permissions, try running this program again in administrator mode.')


if __name__ == "__main__":
    main()
