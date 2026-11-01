"""Public request, response, device and session value types."""
from __future__ import annotations
from dataclasses import dataclass, field
import os
from pathlib import Path
import plistlib

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
    path: Path
    _data: bytes = field(repr=False)

    @classmethod
    def _decode(cls, data: bytes, path: Path) -> Session:
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

    def save(self, filename: str | os.PathLike) -> Path:
        """Save a copy; login already saves the session in the device directory."""
        path = Path(filename).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(self._data)
        return path


