# macOS App Store downloads

[Complete integration guide](full-docs.md) · [Store authentication](store.md)

`AppStoreMacClient` and `apple-auth-appstore --mac` download Mac Store assets and
produce checked XAR installation packages using an existing Mac Accounts session
and Store ADI state. The dpInfo version 3 transport is handled independently in C++.
Build with `APPLE_AUTH_WITH_TESTFLIGHT=ON`; the clients share the SDK HTTPS and
streaming download code. Windows uses Mbed TLS and curl/Schannel.
[C, Python and Swift bindings](full-docs.md#store-bindings) expose the same asset
and package operations.

`AppStoreMacClient` accepts `ClientOptions`; its `headers`, `user_agent` and
`client_info` fields apply to both Store operations and catalog/download metadata
requests. For example, set `options.headers["Accept-Language"] = "pl-PL"`.

## Commands and saved state

These examples use the production TestFlight app (`899247664`) for macOS:

```text
apple-auth-appstore --mac mac-device/store mac-store.plist pl catalog 899247664 TestFlight-Mac-catalog.json
apple-auth-appstore --mac mac-device/store mac-store.plist pl metadata 899247664 TestFlight-Mac-metadata.plist
apple-auth-appstore --mac mac-device/store mac-store.plist pl download 899247664 TestFlight-Mac.asset
apple-auth-appstore --mac mac-device/store mac-store.plist pl package 899247664 TestFlight-Mac.pkg
```

Use the same Store directory (`identity.json` and `adi.pb`) that issued the
session, and the country matching the account storefront. A saved session from
`apple-auth-store mac-login` or `mac-pet-login` is supported; see
[Store authentication](store.md). Downloads never log in, obtain PET, request
2FA, provision missing state or acquire a license. An app must already have a
license for this account. The ordinary iOS `acquire-free` operation is separate;
Mac license acquisition has not been established by this client.

```cpp
#include <apple_auth/appstore.hpp>

auto session = apple_auth::StoreSession::load("mac-store.plist");
apple_auth::AppStoreMacClient mac(session, "mac-device/store", "pl");
auto result = mac.download_package(899247664, "TestFlight-Mac.pkg");
// result.path: checked XAR/pkg; result.original_path: preserved original CDN bytes.
```

## Assets and packages

The client selects `platform=mac` / `platformAttributes.osx` in the public catalog.
It generates hardware6 kbSync and fresh AMD headers for `/ent/download`, using
the saved Store cookies. It does not create another SAP session for download.
The response must match the account, app ID, bundle, macOS platform and catalog
offer. `authorized=false` alone is not a failure when a matching download item
is returned. Account headers and cookies are never sent to the CDN.

The CDN bytes are checked against Store size and MD5 before further processing.
Existing output files are rejected. A private side directory
retains the exact download metadata, including dpInfo and receipt/license
material. `AppStoreMacDownload::version_ids` exposes version identifiers returned
by that response; the client downloads the current selected offer.

`download()` / CLI `download` preserve the original asset, and report remaining
wrapping through `transport_wrapped`. `download_package()` / CLI `package` remove
dpInfo3 using the original hardware6 GUID and return a `.pkg`. The XAR header,
compressed TOC, TOC checksum, member bounds and every archived member checksum
are checked before the output is published. An unwrapped XAR source is also
accepted. Other dpInfo versions are rejected. The package result includes
`package_validated=true`, member count and the output SHA-256; the exact original
asset is retained at `original_path` in the private side directory.

For an already saved pair, `unwrap_appstore_mac_package(source, destination,
hardware6, dp_info88)` performs the same conversion entirely offline.
`AppStoreMacTransport` in `<apple_auth/store_core.hpp>` exposes just the
chunk transform: consecutive 32768-byte chunks, with only the last shorter.
Use that separate API for Mac Store data; the TestFlight iOS profile differs.

## Validation and limits

These integrity checks do not validate the installer certificate trust chain.
The SDK saves a package; it does not install an `.app`, personalize receipts or
decrypt FairPlay content. Installation and launch on an actual Mac have not
been verified.

Previous Windows verification downloaded Mac TestFlight 4.4.0 with saved cookies
and fresh SDK AMD/kbSync. Both the original asset and the unwrapped package matched
independent references byte for byte; all five XAR members passed their checksums.
Offline controls covered wrong platform, app, bundle, offer, account, missing
license, invalid CDN host, changed hardware and damaged input. The CLI `package`
flow reproduced the checked package without a new login or purchase. These were
private integration controls.
