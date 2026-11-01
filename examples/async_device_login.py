#!/usr/bin/env python3
"""Async device/login example. Credential prompts run outside the event loop."""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from apple_auth import AsyncDevice  # noqa: E402


async def main(email):
    async with AsyncDevice.mac("my-mac", model="Mac17,8", macos="27.0.1") as device:
        session = await device.login(email=email)
        headers = await device.headers()
        print(f"Session saved to {session.path}; {len(headers)} fresh headers available.")


if __name__ == "__main__":
    asyncio.run(main(input("Apple ID: ").strip()))
