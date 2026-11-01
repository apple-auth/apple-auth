"""Apple Music Store login with an asynchronous application callback."""
import asyncio

from apple_auth import AsyncDevice


async def main():
    email = await asyncio.to_thread(input, "Apple ID: ")
    async with AsyncDevice.android() as device:
        async def verification():
            return (await asyncio.to_thread(input, "Apple ID verification code: ")).strip()
        await device.login_store(email=email.strip(), two_factor=verification)
        response = await device.store_request("account-flags")
        print(f"Account check: HTTP {response.status}")
        print(f"Private device state: {device.state}")


if __name__ == "__main__":
    asyncio.run(main())
