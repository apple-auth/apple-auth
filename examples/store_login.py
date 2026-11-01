"""Log in to Apple Music Store and save a private reusable session."""
import argparse
from pathlib import Path

from apple_auth import Device


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--state", type=Path, help="Private device directory; defaults to a new one")
    parser.add_argument("--email", help="Apple ID; prompted if omitted")
    parser.add_argument("--reuse", action="store_true", help="Reuse the saved Store session")
    options = parser.parse_args()
    factory = Device.open if options.reuse else Device.android
    if options.reuse and options.state is None:
        parser.error("--reuse requires --state")
    with factory(options.state) as device:
        if options.reuse:
            if device.store_session is None:
                parser.error("No saved Store session in this device directory")
        else:
            device.login_store(email=options.email or input("Apple ID: ").strip())
        response = device.store_request("account-flags")
        print(f"Account check: HTTP {response.status}")
        print(f"Private device state: {device.state}")
        if response.status != 200:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
