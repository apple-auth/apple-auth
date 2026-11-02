# App Store downloads

[Complete integration guide](full-docs.md) · [Store authentication](store.md)

Choose [iOS IPA downloads](#ios-app-store) or
[macOS assets and packages](#macos-app-store).

Build with `APPLE_AUTH_WITH_TESTFLIGHT=ON`; both clients share the SDK HTTPS and
download stack. Windows uses MbedTLS and curl/Schannel.
[C, Python and Swift bindings](full-docs.md#store-bindings) expose the same native clients.

## iOS App Store

`AppStoreIosClient` and `apple-auth-appstore` read the public iOS catalog and
download encrypted IPA files using saved iOS Store cookies.

The constructor accepts optional headers after the transport:

```cpp
apple_auth::AppStoreIosClient client(saved_context, {},
    {{"User-Agent", "MyClient/1.0"}, {"Accept-Language", "pl-PL"}});
```

The same final `Headers` argument is available on the `StoreSession` constructor.
Overrides apply to catalog, metadata and acquisition requests; default calls keep
their existing behavior.

### Saved context

Create a context with `apple-auth-store configurator-login`, then
`apple-auth-store ios-context`; see [the complete workflow](full-docs.md#ios-app-store).
The exported private JSON contains these download fields:

```json
{
  "dsid": "1",
  "guid": "020000000001",
  "country": "pl",
  "storefront": "143478-2,34",
  "storeCookies": {"cookie-name": "saved-cookie-value"}
}
```

The values above are placeholders. Use the account's country/storefront and the
original six-byte Store GUID. A TestFlight hardware20 UDID is a different input.
The cookie mapping must come from a saved iOS-compatible Store session. A
successful Mac Store login or TF exchange alone does not establish that its
cookies authorize ordinary iOS commerce requests.

### Commands

The examples use the production TestFlight app (`899247664`). This is an ordinary
App Store download, separate from downloading an app's TestFlight beta.

```text
apple-auth-appstore saved-ios-store.json catalog 899247664 TestFlight-catalog.json
apple-auth-appstore saved-ios-store.json metadata 899247664 TestFlight-metadata.plist
apple-auth-appstore saved-ios-store.json download 899247664 TestFlight-encrypted.ipa
```

If the account needs a license, explicitly run
`apple-auth-appstore saved-ios-store.json acquire-free 899247664 TestFlight-acquisition.plist`
before requesting metadata/download. The command checks the current price and
requires the exported `passwordToken` and `purchaseUrl`; the minimal JSON above
does not include those acquisition fields.

### Download behavior and limits

Catalog requests use the account country and the MDM enterprise/iPhone/iPad
catalog fallback. Download requests select the iOS offer and generate a fresh
hardware6 kbSync. The client checks the returned account, app, bundle, version
and platform before fetching a CDN URL. The CDN receives no Store headers.
Size and MD5 are checked against Store metadata; every IPA member is read for
CRC validation, and the main Info.plist must declare iPhoneOS. Existing outputs
are rejected. Apple-provided SINF records are inserted by default, using the
package manifest or the main executable's `.sinf` path for a single record
without a manifest. The resulting IPA remains FairPlay encrypted.

The download metadata, SINF/receipt material and original encrypted IPA remain
in a private directory next to the output. Set Python `download(...,
include_sinf=False)`, Swift `includeSinf: false`, the third C++ `download()`
argument to `false`, or CLI `download ... --no-sinf` to publish the original
validated CDN bytes instead. The C function is
`aauth_appstore_ios_client_download_ipa(..., include_sinf, &output)` (`1` include,
`0` skip). Missing SINF records are a no-op; malformed supplied records or unsafe
manifest paths fail without publishing output. `bytes` reports CDN bytes;
`sha256` and `members` describe the resulting IPA.
The client does not decrypt FairPlay, install or run the app. Some Store metadata contains account
identifiers and signed URLs; keep it private.

For content decryption, use
[fairplay-decrypt](https://github.com/EthanArbuckle/fairplay-decrypt) with a
`credential.bin` matching the SINF's **`user` + `key`** selectors. A credential
retrieved for a TestFlight license can differ from the App Store credential even
for the same Apple ID. Use the target App Store IPA/SINF when retrieving it;
see the full guide for selector-based retrieval and cross-app reuse.
See the [decryption example](full-docs.md#decrypting-downloaded-ipas).

The catalog/download client does not log in, obtain PET, request 2FA or acquire
licenses automatically. If an app has no license, or cookies are rejected, it
fails without a login or purchase fallback. `acquire_free()` and the CLI's
`acquire-free` command explicitly request one license after checking the public
price is zero; they require the password token and Store-pod purchase URL.

The completed Configurator password/2FA login is available through
`StoreClient` with `StoreProtocol::configurator`. Its `StoreSession::ios_context()`
export supplies the saved-cookie context, including optional acquisition fields.
`AppStoreIosClient(session, country)` accepts that session directly.
[Authentication APIs and CLI commands](store.md).

The [C++ API](../include/apple_auth/appstore.hpp) also accepts a custom metadata
HTTP transport. CDN streaming uses the SDK's built-in HTTPS downloader.
Previous Windows verification downloaded App Store TestFlight 4.4.1/697.1, matched the
independently downloaded IPA byte for byte, and verified all 709 ZIP members.
Offline controls cover wrong platform, offer, app, bundle, account, missing
license, an invalid CDN host and catalog service errors.

## macOS App Store

`AppStoreMacClient` and `apple-auth-appstore --mac` download Mac Store assets and
produce checked XAR installation packages using an existing Mac Accounts session
and Store ADI state. The dpInfo version 3 transport is handled independently in C++.

`AppStoreMacClient` accepts `ClientOptions`; its `headers`, `user_agent` and
`client_info` fields apply to both Store operations and catalog/download metadata
requests. For example, set `options.headers["Accept-Language"] = "pl-PL"`.

### Commands and saved state

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

### Assets and packages

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

### Validation and limits

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
