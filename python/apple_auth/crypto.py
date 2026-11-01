"""Optional AES-256-GCM session storage, using the SDK's existing MbedTLS backend.

The caller owns key storage. Keys are 32 random bytes, not passwords or Apple tokens.
"""
from __future__ import annotations
import ctypes as c
from pathlib import Path
from .native import Library, _path

__all__ = ["generate_key", "encrypt", "decrypt"]
_MAX_PLAINTEXT = 16 * 1024 * 1024
_MAX_ENVELOPE = _MAX_PLAINTEXT + 37


def _key(value) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("encryption_key must contain 32 raw bytes")
    value = bytes(value)
    if len(value) != 32:
        raise ValueError("Session encryption requires a 32-byte key")
    return value


def _library(value):
    return value if isinstance(value, Library) else Library(value)


def _raw(value):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("Session data must be bytes")
    value = bytes(value)
    return (c.c_uint8 * len(value)).from_buffer_copy(value)


def generate_key(*, library=None) -> bytes:
    """Generate a 32-byte storage key. Persist it separately from encrypted sessions."""
    lib = _library(library)
    return lib._buffer(lib._function("aauth_client_generate_session_key"))


def _transform(name, data, key, library):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("Session data must be bytes")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    limit = _MAX_PLAINTEXT if name == "aauth_client_encrypt_session" else _MAX_ENVELOPE
    if size > limit:
        raise ValueError("Session data exceeds the 16 MiB storage limit")
    key = _key(key)
    lib = _library(library)
    source, secret = _raw(data), _raw(key)
    try:
        return lib._buffer(lib._function(name), source, len(source), secret, len(secret))
    finally:
        c.memset(secret, 0, len(secret))


def encrypt(data: bytes, key: bytes, *, library=None) -> bytes:
    """Encrypt bytes with a fresh random nonce; returns a versioned authenticated envelope."""
    return _transform("aauth_client_encrypt_session", data, key, library)


def decrypt(data: bytes, key: bytes, *, library=None) -> bytes:
    """Authenticate before returning plaintext. Wrong keys and tampering raise NativeError."""
    return _transform("aauth_client_decrypt_session", data, key, library)


def _encode(data, encryption_key, library=None):
    return bytes(data) if encryption_key is None else encrypt(data, encryption_key, library=library)


def _decode(data, encryption_key, library=None):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("Session data must be bytes")
    data = bytes(data)
    if encryption_key is None:
        if data.startswith(b"AAUTHENC"):
            raise ValueError("Encrypted session requires encryption_key")
        return bytes(data)
    return decrypt(data, encryption_key, library=library)


def _read(filename):
    with Path(filename).expanduser().resolve().open("rb") as stream:
        data = stream.read(_MAX_ENVELOPE + 1)
    if len(data) > _MAX_ENVELOPE:
        raise ValueError("Session file exceeds the 16 MiB storage limit")
    return data


def _save(filename, data, encryption_key, library=None, *, overwrite=True):
    lib = _library(library)
    path = Path(filename).expanduser().resolve()
    if not overwrite and path.exists():
        raise FileExistsError("Session output already exists")
    raw = _raw(_encode(data, encryption_key, lib))
    try:
        lib._check(lib._function("aauth_client_save_session")(_path(path), raw, len(raw)))
    finally:
        c.memset(raw, 0, len(raw))
    return path
