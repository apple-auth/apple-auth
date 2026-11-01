# Session serialization and optional encryption

[Complete integration guide](full-docs.md) · [State formats](formats.md)

Sessions can be serialized to bytes for a database, remote storage or a
caller-managed file. Plain `save()` and existing plist APIs keep their behavior.
Passing an encryption key enables AES-256-GCM through the SDK's existing MbedTLS
backend. No extra Python package, Apple framework or mandatory key store is added.

Use a **32-byte random key**. `generate_key()` / `generate_session_key()` /
`SessionCrypto.generateKey()` generate suitable keys. The application must retain
the key separately and supply it again when loading the session. Apple passwords,
PETs, ADI data and SRP keys are not used as storage keys.

## Python

```python
from apple_auth import Device, Session
from apple_auth.crypto import generate_key, encrypt, decrypt

key = generate_key()  # Keep this key in your application's secret storage.

# Protect automatic account and Store session saves in this device directory.
with Device.mac("my-macbook", encryption_key=key) as device:
    session = device.login(email=input("Apple ID: ").strip())

    session.save("session.plist")  # Existing plaintext behavior.
    session.save("session.enc", encryption_key=key)
    encoded = session.serialize(encryption_key=key)
    restored = Session.deserialize(encoded, encryption_key=key)
    loaded = Session.load("session.enc", encryption_key=key)

    # Or let the application choose encryption and its storage backend.
    plaintext = session.serialize()
    ciphertext = encrypt(plaintext, key)
    restored = Session.deserialize(decrypt(ciphertext, key))

# Reopen with the same key, loaded from the application's secret storage.
with Device.open("my-macbook", encryption_key=key) as device:
    session = device.session
```

`AsyncDevice` accepts the same `encryption_key`; its login/load operations use it
off the event loop. The key is copied at construction and is not written to the
device identity or session file.

| API | Parameters and behavior |
| --- | --- |
| `crypto.generate_key` | `library=None`; returns 32 random bytes. |
| `crypto.encrypt`, `crypto.decrypt` | `(data, key, *, library=None)`; byte inputs, 32-byte key. |
| `Session.serialize` | `(*, encryption_key=None, library=None)`; returns the complete account plist or encrypted bytes. |
| `Session.deserialize` | `(data, *, encryption_key=None, library=None)`; returns an in-memory account session with `path=None`. |
| `Session.load`, `Session.save` | `(filename, *, encryption_key=None, library=None)`; file convenience methods. |
| Native `AccountSession`, `StoreSession` | `serialize(*, encryption_key=None)`, `deserialize(data, *, encryption_key=None, library=None)`, `load(filename, *, encryption_key=None, library=None)`, `save(filename, *, encryption_key=None)`. |
| `TestFlightClient` | `serialize(*, encryption_key=None)`, `deserialize(data, *, encryption_key=None, **options)`, `load(filename, *, encryption_key=None, **options)`, `save(filename, *, encryption_key=None)`. Existing client options remain available; saves still reject existing output files. |

`library` selects an existing `Library` or native library path for crypto helpers.
Bound native sessions use their own library. The unencrypted high-level `Session`
byte/file helpers do not need to load a native library.

`Device.developer_session()` still returns its existing dictionary. To protect it,
serialize that mapping with `json.dumps(developer).encode("utf-8")` and pass the
bytes to `encrypt()`. Reverse with `json.loads(decrypt(ciphertext, key))` before
calling `device.developer_headers(developer)`.

## Swift

```swift
import Foundation
import AppleAuth

let key = try SessionCrypto.generateKey()
let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("apple-auth", isDirectory: true)
let file = root.appendingPathComponent("session.enc")

func store(_ session: AccountSession) throws {
    try session.save(to: file, encryptionKey: key)
    let bytes = try session.serialize(encryptionKey: key)
    let restored = try AccountSession.deserialize(bytes, encryptionKey: key)
    let loaded = try AccountSession.load(from: file, encryptionKey: key)
    _ = (restored, loaded)
}

let device = try Device(directory: root.appendingPathComponent("my-macbook", isDirectory: true),
                        encryptionKey: key)
// Subsequent login() and loadSession() use this key for the account file.
```

`StoreSession` and `DeveloperSession` have the same `serialize(encryptionKey:)`,
`deserialize(_:encryptionKey:)`, `save(to:encryptionKey:)` and
`load(from:encryptionKey:)` methods. Their default key is `nil`.
`TestFlightClient` exposes async versions, with its existing `transport` and
`options` arguments on `deserialize` / `load`. Its `savedSession` initializer also
accepts `encryptionKey`. `Device.open` accepts the same key as the initializer.

`SessionCrypto.encrypt(_:key:)` / `decrypt(_:key:)` operate on arbitrary `Data`.
They do not depend on a logged-in device or network access.

## C++

```cpp
#include <apple_auth/client.hpp>
#include <apple_auth/session_crypto.hpp>

auto key = apple_auth::generate_session_key();
auto session = apple_auth::AccountSession::load("session.plist");
auto plaintext = session.serialize();
auto ciphertext = session.serialize(key);
auto restored = apple_auth::AccountSession::deserialize(ciphertext, key);
session.save("session.enc", key);
auto loaded = apple_auth::AccountSession::load("session.enc", key);

auto encoded = apple_auth::encrypt_session(plaintext, key);
auto decoded = apple_auth::decrypt_session(encoded, key);
```

`AccountSession`, `StoreSession` and `DeveloperSession` expose the same byte
serialization and file methods. `serialize` and `deserialize` take an optional
`ByteView` key; omit it for plaintext. Existing account/Store `save(path)` and
`load(path)` overloads remain available; add the key as the second argument to
encrypt or decrypt. Developer Session serialization uses JSON with `account_id`,
`token` and `expires_at_ms`.

`TestFlightClient::serialize(key)` and `save(path, key)` protect its saved JSON.
`deserialize(data, key={}, transport={}, options={})` and
`load(path, key={}, transport={}, options={})` restore it. The download feature
must be enabled for TestFlight; the crypto helpers themselves are part of the core.

## C

The core functions use caller-owned buffers and `aauth_last_error()`:

```c
#include <apple_auth/c_api.h>
#include <stdlib.h>

int protect(const uint8_t *plaintext, size_t size) {
    uint8_t key[32];
    size_t encrypted_size = 0;
    if (aauth_session_key_generate(key, sizeof key) != AAUTH_OK) return 1;
    if (aauth_session_encrypt(plaintext, size, key, sizeof key,
                             NULL, 0, &encrypted_size) != AAUTH_OK) return 1;
    uint8_t *encrypted = malloc(encrypted_size);
    if (!encrypted) return 1;
    aauth_status status = aauth_session_encrypt(plaintext, size, key, sizeof key,
        encrypted, encrypted_size, &encrypted_size);
    /* Store encrypted bytes and retain key separately before returning. */
    free(encrypted);
    return status == AAUTH_OK ? 0 : 1;
}
```

`aauth_session_decrypt(data, size, key, key_size, output, capacity, written)` uses
the same buffer convention. Authentication is checked before plaintext is copied
to the caller. An insufficient capacity changes only `*written`.

For the client library, `aauth_client_generate_session_key`,
`aauth_client_encrypt_session(data, size, key, key_size, output)` and
`aauth_client_decrypt_session(data, size, key, key_size, output)` return an
`aauth_client_buffer`; release it with `aauth_client_buffer_free` and read
`aauth_client_last_error` on failure. They support plaintext up to 16 MiB.
`aauth_client_save_session(filename, data, size)` atomically writes already
serialized bytes with the SDK's private-file permissions.

Obtain account/Store bytes with the existing `aauth_account_session_plist` /
`aauth_store_session_plist` functions. `aauth_testflight_client_serialize` provides
the saved TestFlight JSON. After decryption, pass the plaintext to the existing
from-plist / TestFlight create APIs. Developer Session JSON can be encrypted
directly. All of these operations are independent of SRP and ADI.

## Storage behavior

Python and Swift crypto helpers accept up to 16 MiB of plaintext. Session file
reads are bounded to that size plus the 37-byte encryption envelope.

- Encryption is enabled only when a key is supplied. `plist()` / Swift `plist`
  and plain serialization continue to expose complete plaintext session bytes in memory.
- Each encryption generates a fresh 12-byte random nonce and a 16-byte GCM tag.
  Wrong keys, damaged data and unsupported formats fail; no plaintext fallback is used.
- Pass the key on each explicit encrypted save. `Device` uses its configured key
  automatically; Python Store request persistence also retains the loaded/saved
  Store session's encryption key when updating its cookies.
- Account/Store files can be explicitly migrated by loading the plaintext session
  without a key and saving with a key. Reopen the device with that key afterward.
- This option protects session files. Device identity and ADI provisioning retain
  their existing formats; download artifacts and application-managed exports are separate.

The [versioned envelope format](formats.md#encrypted-session-envelope) is shared
by all four language APIs. Encrypted data contains no key or account identifier
outside the ciphertext.
