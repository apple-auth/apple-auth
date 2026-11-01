# Ordinary iOS App Store downloads

[Complete integration guide](full-docs.md) · [Store authentication](store.md)

For macOS apps, use [the separate Mac client and `--mac` mode](appstore-macos.md).

`AppStoreIosClient` and `apple-auth-appstore` read the public iOS catalog and
download encrypted IPA files using saved iOS Store cookies. Build with
`APPLE_AUTH_WITH_TESTFLIGHT=ON`; both clients share the SDK download and ZIP stack.
On Windows they use MbedTLS and curl/Schannel.
[C, Python and Swift bindings](full-docs.md#store-bindings) use the same native clients.

The constructor accepts optional headers after the transport:

```cpp
apple_auth::AppStoreIosClient client(saved_context, {},
    {{"User-Agent", "MyClient/1.0"}, {"Accept-Language", "pl-PL"}});
```

The same final `Headers` argument is available on the `StoreSession` constructor.
Overrides apply to catalog, metadata and acquisition requests; default calls keep
their existing behavior.

## Saved context

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

## Commands

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

## Download behavior and limits

Catalog requests use the account country and the MDM enterprise/iPhone/iPad
catalog fallback. Download requests select the iOS offer and generate a fresh
hardware6 kbSync. The client checks the returned account, app, bundle, version
and platform before fetching a CDN URL. The CDN receives no Store headers.
Size and MD5 are checked against Store metadata; every IPA member is read for
CRC validation, and the main Info.plist must declare iPhoneOS. Existing outputs
are rejected. The original CDN bytes are published after validation.

The download metadata, SINF/receipt material and original encrypted IPA remain
in a private directory next to the output. The client does not inject SINF,
decrypt FairPlay, install or run the app. Some Store metadata contains account
identifiers and signed URLs; keep it private.

For content decryption, use
[fairplay-decrypt](https://github.com/EthanArbuckle/fairplay-decrypt) with a
`credential.bin` from the **same Apple ID used to download the IPA**.
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
