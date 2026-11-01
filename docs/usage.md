# Usage & build guide

For the capability matrix and complete authentication/download workflows, start
with the [complete integration guide](full-docs.md).

## Build

### macOS

The [README](../README.md#build) uses Homebrew dependencies. It builds for the
host architecture, both Apple Silicon and Intel. Use `mbedtls@3`: Mbed TLS 4
is not supported. Full Xcode is required for iOS builds.

### Linux

Ubuntu 24.04:

```sh
sudo apt install cmake ninja-build g++ libmbedtls-dev libcurl4-gnutls-dev libplist-dev nlohmann-json3-dev
cmake --preset release
cmake --build --preset release
```

### Windows

Visual Studio 2022 and vcpkg:

```powershell
cmake -S . -B build/windows -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build/windows --config Release
```

### Install

```sh
cmake --install build/release --prefix "$PWD/install"
```

For Visual Studio, use `build/windows` and add `--config Release`.

| CMake option | Default | Purpose |
| --- | --- | --- |
| `APPLE_AUTH_WITH_CLIENT` | `ON` | HTTPS, GrandSlam and Store clients |
| `APPLE_AUTH_WITH_CURL` | `ON` on desktop | Built-in transport; `OFF` uses the supplied callback |
| `APPLE_AUTH_WITH_TESTFLIGHT` | `OFF` | TestFlight and iOS/macOS App Store clients; requires client and curl |
| `BUILD_SHARED_LIBS` | `ON` on desktop | Shared libraries, required by Python |
| `APPLE_AUTH_BUILD_EXAMPLES` | `ON` for standalone desktop builds | CLI and OTP tool |
| `APPLE_AUTH_SANITIZERS` | `OFF` | Address/undefined-behavior checks with GCC/Clang |

With vcpkg, core-only builds also need `VCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON`.
The download option adds libzip, zlib and a pinned LZFSE source dependency.
See [the complete build commands](full-docs.md#build-and-install) for enabling it
on each desktop platform. CLI executables also require `APPLE_AUTH_BUILD_EXAMPLES=ON`.

### iOS / iPadOS

On a Mac with Xcode, Python 3.10+, CMake and Ninja:

```sh
python tools/build_apple.py --with-client --include-macos
```

This builds iOS 13+ device/Intel-simulator slices, an iOS 14+ arm64 simulator slice,
and a universal macOS 12+ slice.
`build/apple/package/AppleAuth.zip` is a ready-to-use local Swift package;
`apple_auth.xcframework.zip` contains the native C/C++ library. Dependencies are
merged into the static library. The account client uses CoreFoundation for plists
and Swift's URLSession for HTTP, without curl/libplist. Python is installed separately.
Omit `--with-client` for the transport-independent core only.

GitHub Actions checks macOS shared/static builds on Intel and Apple Silicon,
links all iOS slices, checks Swift imports, and uploads the XCFramework.

## Swift

The [latest release](https://github.com/yummy1gay/apple-auth/releases/latest)
contains `AppleAuth.zip`. Download it, extract it, and choose
**File → Add Package Dependencies → Add Local** in Xcode. Select the `AppleAuth`
directory. The package includes its native libraries and dependencies.
Version tags build and publish the archives plus SHA-256 checksums automatically.

Use the [login example](../examples/ios_login.swift) with an app-private state
directory. `Device` defaults to a synthetic Mac identity, regardless of the host.
`Device.open(directory:)` reuses saved settings; `loadSession()` reads the saved
account session. Native operations run on a serial background queue per device;
verification callbacks are async, cancellation propagates, and errors are thrown.

```swift
let verification = Verification(method: .sms, selectPhone: chooseNumberInUI,
                                code: requestCodeInUI)
let account = try await device.login(email: email, password: password,
                                     verification: verification)
let session = try await device.developerSession(account: account)
let headers = try await device.developerHeaders(session: session)
```

The selection callback receives masked trusted numbers and returns a listed ID.
Use `.automatic` for the server-selected trusted-device/SMS flow. Keep the same
device state for Developer Services calls and request fresh headers for each call.
`DeveloperSession` is Codable for storage in your app's Keychain. Exchanges need
the authenticated session's `sk`/`c` fields; a PET string alone is insufficient.

`headers()` provisions automatically and returns anisette without account login.
`Device(..., transport: HTTPTransport)` supports custom async transports; the default
uses private URLSession cookies, verifies TLS, bounds responses and rejects redirects.
For your own protocol implementation, `SRPHandshake`/`SRPProof` wrap the core C API;
server proof verification precedes session decryption.

## Python

Install with `python -m pip install .` or `-e .`. The wheel contains Python
bindings; build/install the native shared client separately. Checkout and CMake
install layouts are detected automatically. Otherwise set `APPLE_AUTH_LIBRARY`
to the absolute client library path. Windows can also use `APPLE_AUTH_DLL_DIRS`
for dependency directories, separated by semicolons.

| Operation | API |
| --- | --- |
| Create / reopen | `Device.mac(state)`, `Device.iphone(state)`, `Device.windows(state)`, `Device.android(state)` |
| Reopen saved settings | `Device.open(state)` |
| Provision / anisette | `provision()`, `headers()` |
| GrandSlam login / saved session | `login(email=..., password=None, two_factor=None, verification=None)`, `session` |
| Store login / saved session | `login_store(...)`, `store_session` |
| Signed Store request | `store_request(url_or_bag_key, method="GET", body=b"", headers=None)` |

`Device.mac()` accepts `model`, `macos`, `build` and `serial_number`. Any version
and build with valid syntax is accepted; there is no built-in release table.
When selecting a different OS version, supply its matching build explicitly.
Omit both to reuse the saved OS or the default for a new device.
Omit `state` to allocate a local directory.
Use context managers; serialize synchronous operations on each device.
`Device.iphone()` accepts `model`, `ios`, `build` and `serial_number` and keeps
Mac ADI for provisioning. Supply the iOS build when changing the OS version.
Reopen the same directory to update macOS/iOS metadata while retaining the device
ID, hardware binding, provisioning and saved account sessions. The model, platform
and serial number must remain the same. Close the previous instance first.

```python
with Device.mac("my-mac", macos="27.2", build="26B123") as device:
    print(device.info)
```

Every device factory accepts `user_agent`, `client_info` and a `headers` dictionary.
This includes Mac, iPhone, Windows, Android, `Device.open()` and `AsyncDevice`.
`user_agent` sets `User-Agent`; `client_info` sets `X-MMe-Client-Info`.
Empty shortcut values keep the defaults. `headers` can replace these fields and
set other device headers, including locale, time zone, language and app info.
Names are matched without regard to case; duplicate names with different casing
are rejected. Explicit dictionary values take priority over the shortcuts and
later protocol defaults, including on Store and Developer requests.

Overrides belong to the current client instance and do not rewrite saved identity.
Pass them again when reopening a device. Header names must be HTTP tokens; values
must be printable ASCII, at most 4096 bytes each (128 headers / 64 KiB total).

```python
with Device.android("my-android", user_agent="MyAndroid/1.0",
                    client_info="<SM-S918B> <Android;14;UP1A> "
                                "<com.apple.AuthKit/1 (com.apple.android.music/4.9.6)>") as device:
    device.provision()
```

In C++, set `ClientOptions::user_agent` and `ClientOptions::client_info`.
Use `ClientOptions::headers` for arbitrary headers:

```python
with Device.mac("my-mac", headers={
    "User-Agent": "MyClient/1.0",
    "Accept-Language": "pl-PL",
    "X-Apple-Locale": "pl_PL",
    "X-Apple-I-TimeZone": "Europe/Warsaw",
    "X-Apple-Client-App-Name": "MyApp",
}) as device:
    device.provision()
```

Swift's `Device` initializer and `open()` accept `userAgent`, `clientInfo` and
`headers: [String: String]`. The C API provides
`aauth_client_create(&config, &client)` with `aauth_client_config.headers_json`.
It is the single creation entry point; use the current headers and native library together.

Developer Session and trusted-device/SMS 2FA use the same header overrides.
The default Xcode profile is `User-Agent: Xcode`,
`X-Apple-App-Info: com.apple.gs.xcode.auth`, and
`X-Xcode-Version: 27.2 (27B52)`. Override any of them through `headers`;
explicit values win in outgoing requests and `developer_headers()`:

```python
with Device.mac("my-mac", headers={
    "X-Xcode-Version": "27.2 (27B52)",
    "User-Agent": "Xcode",
    "X-Apple-App-Info": "com.apple.gs.xcode.auth",
}) as device:
    developer = device.developer_session()  # Requires a saved authenticated account.
    headers = device.developer_headers(developer)
```

Select SMS explicitly with `Verification`; the high-level device prompts for a
code and, when necessary, a trusted phone number. `two_factor=` remains a code-only
shortcut; pass either it or `verification=`, not both.

```python
from apple_auth import Device, Verification

with Device.mac("my-mac") as device:
    account = device.login(email=input("Apple ID: ").strip(),
                           verification=Verification(method="sms"))
```

`Verification` also accepts `code`, `phone_number_id=0` and `select_phone`.
The selector receives a tuple of `TrustedPhoneNumber(id, display_number)` values
and returns an Apple phone ID. A positive `phone_number_id` skips discovery;
zero discovers the trusted numbers. `method="automatic"` follows Apple's
challenge; `"trusted_device"` requests a trusted-device code. These settings
apply when Apple requires 2FA; they do not force a challenge for a trusted identity.
`AsyncDevice.login()` accepts the same object and awaits async code/phone callbacks.
See [all parameters and examples](full-docs.md#python-verification-options).

The built-in curl transport keeps a handle per transport instance, reusing its
connections, DNS cache and TLS sessions. Copies share that instance and serialize
HTTP operations. The combined system/Apple PEM roots are cached on first use for
the lifetime of the process; restart the process to pick up changed system roots.
Backends without `CAINFO_BLOB` reuse one private PEM file per transport and remove
it when the last copy of the transport is destroyed. Custom transports keep their
own connection and certificate policies.

The `apple-auth` CLI accepts `--user-agent`, `--client-info` and repeated
`--header 'Name: value'` arguments.

Serial numbers are optional for all GrandSlam profiles and are never read from
the host. Unless explicitly supplied, they are omitted from requests, and
Python/Swift device info reports `None`/`nil`.
Custom serials preserve case and accept up to 32 ASCII letters, digits or hyphens.

```python
from apple_auth import Device

with Device.mac("my-macbook") as device:
    session = device.login(email="name@icloud.com")
    headers = device.headers()
```

`AsyncDevice` has the same factories and awaitable operations; saved sessions
load through `load_session()` / `load_store_session()`. Calls serialize per
device, and verification callbacks may be coroutines. See [examples](../examples/).
For custom transports/clocks and request timings, use `Library().client(...)`.

### Apple Music Store

Store sessions use a separate login flow:

```python
from apple_auth import Device

with Device.android("music-device") as device:
    session = device.login_store(email="name@icloud.com")
    response = device.store_request("account-flags")
    print(response.status)
```

Store requests refresh anisette/SAP signatures and persist cookies. Responses
contain `status`, `body` and repeated `headers` pairs.
`login_store()` keeps its Android Music protocol. Mac PET login, explicit
Configurator/Android `StoreClient` instances, context exports and optional
TestFlight/App Store clients are described in [the binding guide](full-docs.md#store-bindings).

## C++ / C / CLI

Installed CMake targets are `apple_auth::core` and `apple_auth::client`.
Pass the install prefix in `CMAKE_PREFIX_PATH`; static consumers also need the
dependency prefixes. Both targets work with `add_subdirectory(apple-auth)`.
Public headers are in [include/apple_auth](../include/apple_auth/).

```sh
apple-auth provision ./my-device --device mac
apple-auth login ./my-device ./credentials.txt
```

The credentials file contains the Apple ID and password on separate lines.
C handles/buffers have explicit release functions; error text is thread-local.

## Platforms

The selected device preset determines the identity sent to Apple and the ADI
backend. It is independent of the host OS: for example, `Device.mac()` also
works on Windows or Linux. Building for iOS does not import system accounts.

| Preset | GrandSlam ADI backend / platform ID | Device description |
| --- | --- | --- |
| `mac` | Mac / `1` | Mac identity; configurable model, macOS version and build. |
| `iphone` | Mac / `1` | iPhone identity; configurable model, iOS version and build. Uses Mac provisioning and OTP. |
| `windows` | Windows / `2` | Windows/iCloud identity. |
| `android` | Android / `4` | Android/Apple Music identity. Trusted-device 2FA verified; SMS verification untested. |

ADI platform IDs and C/C++ device preset values (`DevicePlatform` /
`AAUTH_DEVICE_*`) use separate numbering. Mac, Windows and Android ADI have been
verified against their original implementations.

The iPhone preset has been tested successfully with Apple's servers, but native
iOS ADI has not been investigated. It uses Mac ADI with iPhone Client-Info and
remains experimental and not recommended for use.

## State & protocol limits

See [State and protocol formats](formats.md) for file layouts, saved identity and
session fields, OTP envelopes and SAP signatures.

GrandSlam `login()` uses profile `-2` and a version-5 OTP envelope whose trailer
contains the ADI platform ID from the table above. Authentication and 2FA
endpoints are resolved from Apple's lookup for the selected device preset.

Apple Music Store `login_store()` uses a separate profile (`-1`), provisioning
endpoint and SAP flow. Its CPIM and OTP format version is `4`; the Store OTP has
no GrandSlam platform trailer. OTP format versions and ADI platform IDs are
separate protocol fields.

Keep state directories private and copy them whole when moving identities.
GrandSlam uses `adi.pb`; Store uses `store/adi.pb`. Saved platform/model/serial
values must match when reopening; OS version/build can be updated together.
For RAM-only state and optional encrypted snapshots, see [in-memory state](in-memory-state.md).
Loading a saved account session does not check server-side expiry. GrandSlam supports
trusted-device and SMS verification. Optional C++/CLI app downloads are documented
in [the complete guide](full-docs.md#authentication-and-download-workflows).
Apple Music media downloading and FairPlay content decryption are outside this API.

HTTPS verifies certificates and hostnames and supplements system roots with
Apple Root CA and Root CA G3. Windows uses Schannel; Homebrew curl uses its
configured CA bundle. Swift uses the Apple system trust store. Redirects are handled explicitly
and response sizes are bounded. Apple builds use CoreFoundation plists; other
platforms use libplist.
