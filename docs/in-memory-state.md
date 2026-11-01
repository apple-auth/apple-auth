# In-memory device state

State storage is independent of the selected device preset and HTTP transport.
A client may keep its identity, ADI and saved session bytes entirely in RAM,
without creating identity/profile/session files or a temporary state directory.
The existing directory-backed constructors still persist private files.

## C++

```cpp
#include <apple_auth/client.hpp>

apple_auth::ClientOptions options;
options.device_platform = apple_auth::DevicePlatform::mac;
apple_auth::Client device(options); // RAM; no state directory.
auto account = device.login(email, password, request_code);

// The C++ login returns its session; explicitly include it in device snapshots.
device.set_session_data(account.serialize());
auto state = device.serialize_state();

apple_auth::Client restored(state, options);
auto saved = apple_auth::AccountSession::deserialize(restored.session_data());
auto developer = restored.developer_session(saved);
```

`Client(directory, options)` selects files. `Client(state, options, key)` restores
snapshot bytes into RAM; the optional third argument decrypts the snapshot.
`serialize_state(key)` encrypts the whole snapshot. Keys are 32 raw bytes,
generated with `generate_session_key()` and retained by the application.

`session_data(kind)` and `set_session_data(data, kind)` handle opaque serialized
bytes. `kind` defaults to `SessionKind::account`; use `SessionKind::store` for Store
sessions. Empty data represents an absent session. These helpers do not validate
tokens or check their expiry. The C++ client does not automatically save a login
result: choose when and how to serialize it.

## Swift

```swift
import AppleAuth

let key = try SessionCrypto.generateKey() // Retain separately.
let device = try Device(encryptionKey: key) // RAM, Mac preset by default.
let account = try await device.login(email: email, password: password,
    verification: Verification(code: requestCode))
let state = try await device.serializeState() // Encrypted with the device key.
try await device.close()

let restored = try Device(initialState: state, encryptionKey: key)
let saved = try await restored.loadSession()
let headers = try await restored.headers() // Reuses restored ADI provisioning.
try await restored.close()
```

Initializer parameters:

| Parameter | Default / behavior |
| --- | --- |
| `directory` | `nil`: RAM. A file URL selects directory-backed state. |
| `initialState` | `nil`: create a new identity. Snapshot `Data` restores into RAM; cannot be combined with `directory`. |
| `platform` | Omitted: Mac for new devices, saved preset for restored snapshots. An explicit preset must match restored state. |
| `encryptionKey` | `nil`: plaintext sessions and snapshots. A 32-byte key protects automatic account saves and `serializeState()`; pass the same key when restoring. |

Other metadata, header, clock and transport parameters are unchanged.
`directory` is an optional URL and is `nil` for a RAM device.
`Device(directory: root)` retains file storage; `Device.open(directory:)` still
requires an existing identity. Login automatically saves account bytes through
the selected backend, so `loadSession()` works in both modes. Store sessions
returned by `loginStoreWithPET` remain caller-managed; serialize them separately
when needed.

## Python

```python
from apple_auth import Device
from apple_auth.crypto import generate_key

key = generate_key()  # Retain separately.
with Device.memory(encryption_key=key) as device:
    account = device.login(email="name@example.invalid")
    state = device.serialize_state()
    assert device.state is None

with Device.memory(initial_state=state, encryption_key=key) as restored:
    account = restored.session
    headers = restored.headers()
```

`Device.memory(initial_state=None, platform=None, **options)` uses a new Mac
preset unless restoring a snapshot, in which case it reuses the saved preset.
All ordinary device options remain available. `Device(..., in_memory=True,
initial_state=state)` is the equivalent constructor form. A memory device cannot
have a state directory; the old `Device.mac()`/`Device.iphone()` default behavior
still allocates a directory when no path is given.

`Device.serialize_state()` uses its configured `encryption_key` and includes
automatically saved account/ordinary Store sessions. For async applications use
`AsyncDevice.memory(...)`, `await device.serialize_state()` and
`await restored.load_session()`. The async constructor copies incoming bytes and
keys before dispatching initialization.

Low-level `Library.client(directory=None, initial_state=None, ...)` also supports
RAM. It expects plaintext initial snapshot bytes; decrypt them with
`apple_auth.crypto.decrypt` when needed. Its `serialize_state(encryption_key=None)`
can optionally encrypt exports. Low-level session slots use
`client.session_data(kind="account")` and
`client.set_session_data(data, kind="store")`; callers control their serialization.

## C

```c
#include <apple_auth/client_c_api.h>

aauth_client_config config = {0};
config.platform = AAUTH_DEVICE_MAC;
aauth_client* device = NULL;
aauth_status status = aauth_client_create(&config, &device); // directory=NULL: RAM.
if (status != AAUTH_OK) { /* handle error */ }

aauth_client_buffer state = {0};
status = aauth_client_state(device, &state);
if (status == AAUTH_OK) {
    aauth_client_config saved = {0};
    saved.state = state.data;
    saved.state_size = state.size;
    aauth_client* restored = NULL;
    status = aauth_client_create(&saved, &restored);
    if (status == AAUTH_OK) { aauth_client_free(restored); }
    aauth_client_buffer_free(&state);
}
aauth_client_free(device);
```

There is one creation function. `aauth_client_config.directory=NULL` selects RAM;
a nonempty directory string selects files. `state,state_size` restores plaintext
snapshot bytes into RAM. Configuration data is copied before create returns;
callbacks and their context must remain alive for the client lifetime.

Session slots use `aauth_client_session_data(client, AAUTH_SESSION_ACCOUNT,
&output)` and `aauth_client_set_session_data(client, AAUTH_SESSION_STORE, data,
size)`. C exports are plaintext; opt into encryption using
`aauth_client_encrypt_session` / `aauth_client_decrypt_session`, then pass the
decrypted bytes to create. Free SDK-owned output buffers with
`aauth_client_buffer_free`.

## Snapshot format and boundaries

Plaintext snapshots are UTF-8 JSON:

```json
{
  "kind": "apple-auth-state",
  "version": 1,
  "files": {
    "identity.json": "BASE64_ENCODED_IDENTITY",
    "adi.pb": "BASE64_ENCODED_PROFILE",
    "account-session.plist": "BASE64_ENCODED_SESSION"
  }
}
```

`identity.json` is mandatory. The only allowed record names are `identity.json`,
`adi.pb`, `account-session.plist`, `store-account-session.plist`,
`store/identity.json`, and `store/adi.pb`. Optional records are omitted when absent.
Unknown names and path traversal are rejected. Plaintext snapshots are limited
to 16 MiB, including JSON/base64 overhead. Encrypted snapshots add the documented
37-byte AES-GCM envelope. Snapshots use the same format across language APIs.

Snapshots include only saved state. Transport callbacks, observers, clocks,
header overrides, encryption keys, HTTP connections/caches, SAP handshakes and
standalone session objects are not serialized. Supply runtime options again on
restore. Developer Sessions have their own serialization API. Restoring ADI
avoids reprovisioning; it does not guarantee that Apple still accepts an expired
account or Store token.

A snapshot contains device provisioning secrets and may include account/Store
credentials. Use the optional encryption APIs or your own protected storage when retaining it. RAM
mode keeps device state off disk; TLS transports still use their ordinary system
trust configuration, including a public-certificate PEM fallback on older curl
backends.
