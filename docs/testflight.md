# TestFlight catalog and encrypted IPA downloads

[Complete integration guide](full-docs.md) · [Store authentication](store.md)

The optional C++ TestFlight module uses the existing SDK crypto and HTTPS stack:
MbedTLS primitives and curl with Schannel on Windows. ZIP processing adds
libzip/zlib and a pinned open-source LZFSE decoder.
It also has [C, Python and Swift bindings](full-docs.md#store-bindings), enabled
by the same native build option.

Authentication uses Mac PET → Mac SAP1 → Mac Store authentication → a new Mac
TestFlight session. Configurator password/2FA is the separate ordinary iOS App
Store path described in [Store authentication](store.md).

Enable it when configuring the SDK:

```sh
cmake -S . -B build/testflight -DAPPLE_AUTH_WITH_TESTFLIGHT=ON
cmake --build build/testflight --config Release
```

With vcpkg, CMake selects the `client` and `testflight` manifest features before
toolchain initialization. Without vcpkg, provide the regular SDK dependencies,
libzip and zlib through your package manager or `CMAKE_PREFIX_PATH`.
LZFSE is fetched at the pinned commit; `FETCHCONTENT_SOURCE_DIR_LZFSE` supports
an existing source checkout for offline builds. CLI tools require
`APPLE_AUTH_BUILD_EXAMPLES=ON`; see [all desktop build commands](full-docs.md#build-and-install).

## Session and commands

```text
apple-auth-testflight --tf-session-from-cookies saved-store-context.json --output tf-session.json
apple-auth-testflight --tf-catalog --tf-session tf-session.json --output tf-catalog.json
apple-auth-testflight --tf-install com.example.notes --tf-session tf-session.json --output Notes-install.json
apple-auth-testflight --tf-download com.example.notes --tf-session tf-session.json --output Notes-beta-encrypted.ipa
```

`com.example.notes` is a placeholder. Use an available iOS beta bundle ID from
your account's catalog. The SDK does not enroll the account in a beta or accept
invitations. The production TestFlight app's numeric App Store ID is not a beta
bundle ID.

The Store context is JSON containing `dsid`, a hexadecimal 20-byte `udid`, a saved
`storeCookies` mapping, and macOS TestFlight `headers`. The resulting session file
contains account/session identifiers, the matching identity and device headers.
The [profile schema and export workflow](full-docs.md#testflight-profile) describe
each required input and which fields the Store adapter supplies.
Keep these files private. The client never performs a Store/GSA login or requests
2FA when saved data is rejected.

## Download behavior

Downloads select an available iOS build from the catalog, generate a fresh
kbSync212, request install metadata, stream the CDN file, derive transport
parameters from hardware20/dpInfo88, and normalize Apple ZIP into ordinary Deflate.
The CDN receives the signed URL without TestFlight authentication headers or cookies.
Apple-provided SINF records are added to `SC_Info` by default, following the
package's `SC_Info/Manifest.plist`. A single record without a manifest uses the
main executable's `.sinf` path. `META-INF/com.apple.ZipMetadata.plist` is Apple's
archive metadata (record count, file/directory permissions, uncompressed size
and creator-tool details); it is retained from the source package.
Intermediate files are retained beside the
requested output in a separate directory. Existing outputs are rejected; the
IPA is published after ZIP validation and SINF path/count checks.

FairPlay content encryption remains in the IPA. Adding Apple's SINF records does
not decrypt Mach-O content or provide a FairPlay credential.

Set `include_sinf=False` on Python `download()`, `includeSinf: false` in Swift,
or the third `download()` argument to `false` in C++ to skip SINF insertion.
The CLI accepts `--tf-download ... --no-sinf`. The C function
`aauth_testflight_client_download_ipa(..., include_sinf, &output)` takes `1` to
include Apple's records or `0` to skip them. Missing records are a no-op;
malformed supplied records or manifest mappings fail without publishing an IPA.

The downloaded IPA can be decrypted with
[fairplay-decrypt](https://github.com/EthanArbuckle/fairplay-decrypt), using a
`credential.bin` matching the target SINF's **`user` + `key`** selectors. The same
Apple ID alone does not guarantee the same credential: App Store and TestFlight
licenses can use different selectors. Retrieve the credential using the target
TestFlight IPA/SINF, rather than accepting an automatically selected App Store
license. Credentials can work across apps sharing the selectors; do not assume
that there are universally exactly two credentials.
See the [decryption example](full-docs.md#decrypting-downloaded-ipas).

Fresh Store sign-in with the independent macOS SAP signer was accepted in a C++
control, followed by a complete TF/IPA download using its new cookies. That login
path is now exposed through `Client::login_store_with_pet()` and `apple-auth-store`.
`TestFlightClient::from_store_session()` connects the new Store session directly
to the existing TF flow. See [Store authentication](store.md). The original live
control reused existing Mac/Store ADI profiles; integration is checked offline.

## C++ API

The C++ APIs are declared in [testflight.hpp](../include/apple_auth/testflight.hpp)
and [store_core.hpp](../include/apple_auth/store_core.hpp).
`testflight_core.hpp` remains a compatibility include for the shared Store core.
`TestFlightClient` provides session creation/persistence, catalog, install metadata
and downloads. `generate_kbsync` and `TestFlightTransport` are implemented in the core
library. The generator supports the verified fixed macOS27 profile; an empty entropy
span uses the SDK CSPRNG. Explicit entropy is intended for reproducible comparisons.

Pass `TestFlightOptions` as the final argument to the constructor,
`from_store_cookies()` or `from_store_session()` to override request headers,
the install device model and the device name. Existing overloads retain their defaults.

```cpp
apple_auth::TestFlightOptions options;
options.device_model = "iPhone18,2";
options.device_name = "My iPhone";
options.headers = {{"User-Agent", "MyClient/1.0"}, {"Accept-Language", "pl-PL"}};
apple_auth::TestFlightClient client(saved_session, {}, options);
```

Saved `deviceModel`, `deviceName` and `headers` values are used when no override
is supplied. Request IDs and session digests are generated for each request after
the configurable headers have been applied.

`generate_kbsync` accepts the original six-byte Store hardware ID or twenty-byte
TestFlight hardware ID. Keep its length: padding a six-byte ID with zeroes changes
key derivation. TestFlight transport and session APIs still require hardware20.
The low-level hardware6 generator does not itself provide an ordinary iOS App Store
purchase/download client.

## Validation and limits

Previous Windows verification covered a new Mac TF session from saved cookies,
a complete beta IPA download, all member CRCs and comparison with preserved
reference contents. The core matched four full native kbSync packets: three
hardware20 vectors including a synthetic identity and independently chosen entropy,
and a hardware6 Store vector. ZIP64/Apple99 and corrupt,
unsafe-path, truncated and inconsistent-header controls were also checked.
