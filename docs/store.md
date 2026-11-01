# Mac Store and Configurator authentication

[Complete integration guide](full-docs.md) · [Usage and build](usage.md)

The C++ client includes the completed Mac SAP and Store authentication paths.
They use the SDK's Mbed TLS crypto and HTTPS transport. Windows HTTPS uses
curl/Schannel.

| Path | Public API |
| --- | --- |
| Mac GrandSlam → PET | `Client` with `DevicePlatform::mac`, then `login()` |
| Saved PET → Mac SAP1 → Store session | `Client::login_store_with_pet()` |
| Configurator password → Mac SAP1 → 2FA → iOS Store session | `StoreClient` with `StoreProtocol::configurator`, then `login()` |
| Mac Store session → new TF session → iOS catalog → encrypted IPA | `TestFlightClient::from_store_session()` and `download()` |
| Configurator session → ordinary iOS catalog / encrypted IPA | `AppStoreIosClient(session, country)` |
| Mac Store session → macOS catalog / original asset / checked package | `AppStoreMacClient(session, store_directory, country)` |
| Explicit free-app license acquisition | `AppStoreIosClient::acquire_free()` |
| Fresh hardware6/hardware20 kbSync and TestFlight transport removal | `generate_kbsync()` and `TestFlightTransport` |

Store authentication and the Store CLI are built with the regular client.
TestFlight and ordinary App Store catalog/download APIs additionally require
`APPLE_AUTH_WITH_TESTFLIGHT=ON`. C, Python and Swift expose the same Store
protocols and optional download clients. The original `Client::login_store()`
and Python `Device.login_store()` keep their Android Music behavior;
select Configurator with `StoreClient`, or use `login_store_with_pet()` for Mac.
See [binding examples and ownership rules](full-docs.md#store-bindings).

## Mac PET → Store → TestFlight

```cpp
#include <apple_auth/client.hpp>
#include <apple_auth/testflight.hpp>

apple_auth::ClientOptions options;
options.device_platform = apple_auth::DevicePlatform::mac;
apple_auth::Client device("mac-device", options);
auto account = device.login(email, password, request_verification_code);
auto store = device.login_store_with_pet(email, account);
store.save("mac-store.plist");

// Keep the same hardware20 and macOS TestFlight profile for this TF identity.
auto tf = apple_auth::TestFlightClient::from_store_session(
    store, tf_hardware20, mac_tf_headers);
tf.save("tf-session.json");
tf.download("com.example.notes", "Notes-beta-encrypted.ipa");
```

`tf_hardware20` is the original twenty-byte TestFlight identity; it is separate
from the six-byte Store GUID. `mac_tf_headers` contains the macOS TestFlight
profile described in [TestFlight](testflight.md). The adapter supplies the Store
DSID, root Apple cookies, AMD machine ID and storefront from the new Store session.
It does not convert Mac cookies into ordinary iOS App Store cookies.
See the [complete profile schema](full-docs.md#testflight-profile).
`com.example.notes` is a placeholder for an available iOS beta bundle in your catalog.

To reuse an existing PET, load it with `AccountSession::load()` and call
`login_store_with_pet()` directly. This method never runs GrandSlam or refreshes
PET. It verifies the saved account/token pair and expiry before making requests.
The Store account identifier comes from GSA **DsPrsId**; `account_id` is ADSID.
Store anisette and GrandSlam device headers are generated separately.

The lower-level equivalent is `StoreClient(directory, StoreProtocol::macos_accounts,
options).login_with_pet(email, account, fresh_device_headers_callback)`.
The original `StoreClient(directory, options)` and `Client::login_store()` retain
their Android Apple Music protocol.

## Configurator → iOS cookies → ordinary App Store

```cpp
#include <apple_auth/appstore.hpp>

apple_auth::StoreClient configurator(
    "configurator-device", apple_auth::StoreProtocol::configurator);
auto session = configurator.login(email, password, request_verification_code);
session.save("ios-store.plist");
session.save_ios_context("ios-store.json", "pl");

apple_auth::AppStoreIosClient ios(session, "pl");
// Explicitly request this only when a free app needs an account license.
auto acquisition_response = ios.acquire_free(899247664);
ios.download(899247664, "TestFlight-encrypted.ipa");
```

This example uses the production TestFlight app, an ordinary App Store listing.

Configurator fetches the legacy bag, creates a fresh Mac SAP1 session and signs
the raw-password request with `credentialSource=0`. It keeps that same SAP
session and challenge cookies across the verification callback and Store-pod
redirect. It does not use ADI, GrandSlam or PET. The verified initial storefront
is Poland (`143478-2,13`); the response storefront is saved with the session.
Supply the matching account country when exporting an iOS context.

`acquire_free()` checks the current public price without authentication headers,
then sends one zero-price request to the Store pod saved during Configurator
login. A paid or unknown price fails before purchase. The result must confirm
purchase success for the same account. There is no paid-purchase mode, purchase
retry or automatic acquisition during download. Older cookie-only JSON contexts
can still download, but acquisition additionally needs `passwordToken` and
`purchaseUrl`; Configurator context export includes them.

## Command line

```text
# Fresh Mac GrandSlam/PET and Store login:
apple-auth-store mac-login mac-device credentials.txt mac-store.plist

# Alternatively, an existing Mac account-session.plist, without GSA login:
apple-auth-store mac-pet-login mac-device name@example.invalid mac-device/account-session.plist mac-store.plist

apple-auth-store tf-context mac-store.plist mac-tf-profile.json tf-store-context.json
apple-auth-testflight --tf-session-from-cookies tf-store-context.json --output tf-session.json
apple-auth-testflight --tf-catalog --tf-session tf-session.json --output tf-catalog.json
apple-auth-testflight --tf-download com.example.notes --tf-session tf-session.json --output Notes-beta-encrypted.ipa

apple-auth-store configurator-login configurator-device credentials.txt ios-store.plist
apple-auth-store ios-context ios-store.plist pl ios-store.json
apple-auth-appstore ios-store.json acquire-free 899247664 TestFlight-acquisition.plist
apple-auth-appstore ios-store.json download 899247664 TestFlight-encrypted.ipa
```

The credentials file contains email and password on separate lines. Verification
is read interactively when requested. `mac-tf-profile.json` contains `udid` as
forty hexadecimal digits and a `headers` object with the macOS TestFlight profile.
The export commands perform no network requests. New session/context output
paths are required by the CLI. SDK context writers use the private-file helper.

Account sessions, Store sessions, contexts, tokens and acquisition responses
are private inputs/outputs. They are never printed by the CLI or bundled in
the repository. Authentication errors and rate limits are returned to the caller;
saved-session failures never cause an automatic login or PET request.

## Validation and scope

Previous independent C++ controls completed fresh Mac PET → Mac SAP1 →
Store authentication → new TF session → an encrypted beta IPA. Separate
Configurator controls completed password/2FA → new iOS cookies → an App Store
TestFlight IPA, plus explicit free-app license acquisition and download.
The original Mac control reused provisioned Mac/Store ADI profiles; it did not
establish a new cold-start Mac Store provisioning result. Its accepted request
used ADSID in `X-DSID`; the integrated implementation uses DsPrsId and checks
that distinction offline. No new account login is needed to verify this port.

SAP setup, signatures, fresh kbSync and dpInfo processing are implemented in C++.
`SapSession(certificate, SapPlatform::macos)` is also available without HTTP.
`ClientOptions::sap_entropy` optionally supplies explicit entropy for reproducible
offline comparisons; normal operation uses a fresh SDK CSPRNG value.

Both download paths preserve FairPlay content encryption. The SDK does not
include iOS SAP, credential extraction or content decryption.

macOS Store delivery assets can also be fetched from the Mac session, using
`apple-auth-appstore --mac`. [Mac commands and output format](appstore.md#macos-app-store).
The `download` command preserves the original asset and any transport wrapping;
`package` removes dpInfo3 and validates the resulting XAR `.pkg`. Installer
certificate trust and installation/launch on a Mac are not verified by the SDK.
