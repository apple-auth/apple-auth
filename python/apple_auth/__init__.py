"""Apple authentication, Store protocols and optional TestFlight/App Store downloads."""
from .models import DeviceInfo, HttpRequest, HttpResponse, HttpTiming, Session, TrustedPhoneNumber, Verification
from .native import AccountSession, Client, DEVICE_PLATFORMS, Library, NativeError, StoreSession, find_library
from .device import Device
from .async_device import AsyncDevice
from .store import (StoreClient, TestFlightClient, AppStoreIosClient, AppStoreMacClient,
                    STORE_PROTOCOLS, generate_kbsync, unwrap_testflight_transport,
                    normalize_testflight_ipa, unwrap_appstore_mac_package)

__version__ = "0.1.2"
__all__ = [
    "AccountSession", "AsyncDevice", "Client", "DEVICE_PLATFORMS", "Device", "DeviceInfo",
    "HttpRequest", "HttpResponse", "HttpTiming", "Library", "NativeError", "Session",
    "TrustedPhoneNumber", "Verification",
    "StoreSession", "find_library",
    "StoreClient", "TestFlightClient", "AppStoreIosClient", "AppStoreMacClient",
    "STORE_PROTOCOLS", "generate_kbsync", "unwrap_testflight_transport",
    "normalize_testflight_ipa", "unwrap_appstore_mac_package",
]
