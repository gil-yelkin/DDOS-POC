import DDOS
import AntiDoS
from typing import Callable, NoReturn
from Helper import exit_program


def detect_DoS_wrapper() -> NoReturn:
    print('Scanning incoming traffic for malicious activity...')
    attackers: list[str] = AntiDoS.detect_DoS()
    num_attackers = len(attackers)
    print(f'{num_attackers} threats found{", all good :)" if num_attackers == 0 else (": " + str(attackers))}')
    for ip in attackers:
        if input(f'Do you wish to block {ip} in your firewall?') == '0':
            AntiDoS.block_ip_in_firewall(ip)
            print()


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
            print(f'An error occurred:\n{e}')
            print('Insufficient permissions, try running this program again in administrator mode.')


if __name__ == "__main__":
    main()
