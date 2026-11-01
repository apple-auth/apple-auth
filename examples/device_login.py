#!/usr/bin/env python3
"""A persistent Mac, interactive login and fresh headers using the small Python API."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from apple_auth import Device  # noqa: E402


if __name__ == "__main__":
    with Device.mac("my-mac", model="Mac17,8", macos="27.0.1", build="26A434") as device:
        session = device.login(email=input("Apple ID: ").strip())
        headers = device.headers()
        print(f"Session saved to {session.path}; {len(headers)} fresh headers available.")
