"""Public request, response, device and session value types."""
from __future__ import annotations
from dataclasses import dataclass, field
import os
from pathlib import Path
import plistlib
from typing import Awaitable, Callable, Literal


@dataclass(frozen=True)
class TrustedPhoneNumber:
    """Apple's phone identifier and masked display number; not a list index."""

    id: int
    display_number: str


@dataclass(frozen=True)
class Verification:
    """GrandSlam verification options. AsyncDevice also awaits async callbacks."""

    code: Callable[[], str | Awaitable[str]] | None = None
    method: Literal["automatic", "trusted_device", "sms"] = "automatic"
    phone_number_id: int = 0
    select_phone: Callable[[tuple[TrustedPhoneNumber, ...]], int | Awaitable[int]] | None = None

    def __post_init__(self):
        if self.method not in ("automatic", "trusted_device", "sms"):
            raise ValueError("Verification method must be automatic, trusted_device or sms")
        if type(self.phone_number_id) is not int or not 0 <= self.phone_number_id < 2**63:
            raise ValueError("phone_number_id must be a non-negative signed 64-bit integer")
        if self.code is not None and not callable(self.code):
            raise TypeError("Verification code must be a callback")
        if self.select_phone is not None and not callable(self.select_phone):
            raise TypeError("select_phone must be a callback")


def _verification(two_factor, verification):
    if verification is not None and not isinstance(verification, Verification):
        raise TypeError("verification must be a Verification object")
    if verification is not None and two_factor is not None:
        raise ValueError("Pass either two_factor or verification, not both")
    return verification if verification is not None else Verification(code=two_factor)

@dataclass(frozen=True)
class HttpRequest:
    url: str
    method: str
    headers: dict[str, str] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes = field(repr=False)
    headers: tuple[tuple[str, str], ...] | dict[str, str] = field(default=(), repr=False)


@dataclass(frozen=True)
class HttpTiming:
    method: str
    host: str
    path: str
    status: int
    seconds: float


@dataclass(frozen=True)
class DeviceInfo:
    """Resolved, persistent device description. A missing serial is represented by None."""

    platform: str
    model: str | None = None
    os_version: str | None = None
    os_build: str | None = None
    serial_number: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Session:
    """Saved login result, independent of the native client's lifetime."""

    account_id: str
    pet: str = field(repr=False)
    path: Path | None
    _data: bytes = field(repr=False)

    @classmethod
    def _decode(cls, data: bytes, path: Path | None) -> Session:
        fields = plistlib.loads(data)
        try:
            account_id = fields["adsid"]
            pet = fields["t"]["com.apple.gs.idms.pet"]["token"]
            if fields.get("status-code") != 200 or not isinstance(account_id, str) or not isinstance(pet, str):
                raise ValueError("Invalid saved account session")
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("Invalid saved account session") from error
        return cls(account_id=account_id, pet=pet, path=path, _data=data)

    def plist(self) -> bytes:
        """Return the original binary/XML plist when an integration needs it."""
        return self._data

    def serialize(self, *, encryption_key=None, library=None) -> bytes:
        """Return session bytes for any storage backend; encryption is opt-in."""
        from .crypto import _encode
        return _encode(self._data, encryption_key, library)

    @classmethod
    def deserialize(cls, data: bytes, *, encryption_key=None, library=None) -> Session:
        from .crypto import _decode
        return cls._decode(_decode(data, encryption_key, library), None)

    @classmethod
    def load(cls, filename: str | os.PathLike, *, encryption_key=None, library=None) -> Session:
        from .crypto import _decode, _read
        path = Path(filename).expanduser().resolve()
        return cls._decode(_decode(_read(path), encryption_key, library), path)

    def save(self, filename: str | os.PathLike, *, encryption_key=None, library=None) -> Path:
        """Save a copy; login already saves the session in the device directory."""
        if encryption_key is not None:
            from .crypto import _save
            return _save(filename, self._data, encryption_key, library)
        path = Path(filename).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(self._data)
        return path


