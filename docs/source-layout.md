# Source layout

The public headers live in `include/apple_auth`. Private implementation headers
and data stay under `src`; modules include them from that source root.

| Directory | Responsibility |
| --- | --- |
| `src/adi` | Device identity, provisioning, state and OTP |
| `src/sap` | SAP certificates, session establishment and signing |
| `src/store` | Shared Store/TestFlight kbSync and dpInfo primitives |
| `src/client` | Account sessions, HTTP, plist and shared file downloads |
| `src/archive` | IPA/ZIP and Mach-O inspection and normalization |
| `src/appstore` | iOS/macOS Store clients and XAR/package validation |
| `src/testflight` | TestFlight sessions, catalog and download orchestration |
| `src/crypto` | Shared cryptographic backend |
| `src/api` | C entry points |

Store primitives use `apple_auth::detail::kbsync` and
`apple_auth::detail::store_transport`. They reuse the existing crypto backend;
neither depends on an HTTP client or archive library. App Store and TestFlight
clients share archive and download helpers without depending on each other's
private engines.

`<apple_auth/store_core.hpp>` declares the shared public primitives.
`<apple_auth/testflight_core.hpp>` remains a compatibility include. The existing
`APPLE_AUTH_WITH_TESTFLIGHT` build option continues to enable Store/TestFlight
downloads and their dependencies.

## Fixed data

Algorithm tables, fixed keys, masks, profiles and arithmetic coefficients belong
in private `data` headers, following `src/adi/data`. Store and SAP decode them
with the common `src/data_mask.hpp` helper. TestFlight's fixed request salt follows
the same convention in `src/testflight/data`. Shared Store client profiles live
in `src/client/data`; App Store request data lives in `src/appstore/data`.

Use `tools/mask_constants.py` to encode new integer data. Choose the element width
explicitly (`--bits 8`, `16` or `32`) and keep the seed with its encoded initializer.
Decode once into `inline const` or function-local `static const` storage. Traverse
mixed-field records with a field visitor, so padding and host byte order do not
affect decoding. Dependent values must be defined after the data they use.

Keep original byte sequences, keys and unmasked copies out of committed comments,
fixtures and generators as well as production initializers. Sizes, loop bounds
and standard file-format structure remain ordinary code.
