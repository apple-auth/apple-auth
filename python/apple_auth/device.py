"""Persistent device workflow and automatic account-session persistence."""
from __future__ import annotations
import getpass
from dataclasses import replace
import os
from pathlib import Path
from typing import Callable
from uuid import uuid4
from .models import DeviceInfo, HttpRequest, HttpResponse, Session, TrustedPhoneNumber, Verification, _verification
from .native import AccountSession, Library, StoreSession

def _new_device_directory() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return root / "apple-auth" / "devices" / uuid4().hex


def _prompt_phone(phones: tuple[TrustedPhoneNumber, ...]) -> int:
    if len(phones) == 1:
        return phones[0].id
    for index, phone in enumerate(phones, 1):
        print(f"{index}. {phone.display_number}")
    choice = int(input("Trusted phone number [1]: ").strip() or "1")
    if not 1 <= choice <= len(phones):
        raise ValueError("Invalid trusted phone number choice")
    return phones[choice - 1].id


class Device:
    """Create or reopen a device, log in and obtain fresh headers in a few calls.

    Construction only creates/opens local identity. Provisioning is automatic on
    headers() or login(). Calls on one device are serial. Use close() or a context
    manager to release its native client; saved state and sessions remain usable.
    """

    def __init__(self, state: str | os.PathLike | None = None, *,
                 platform: str | None = None, model: str | None = None,
                 os_version: str | None = None, os_build: str | None = None,
                 serial_number: str | None = None,
                 user_agent: str | None = None, client_info: str | None = None,
                 headers: dict[str, str] | None = None,
                 encryption_key: bytes | None = None,
                 in_memory: bool = False, initial_state: bytes | None = None,
                 library: Library | str | os.PathLike | None = None,
                 transport: Callable[[HttpRequest], HttpResponse] | None = None,
                 clock: Callable[[], int] | None = None):
        from .crypto import _key
        self._encryption_key = _key(encryption_key) if encryption_key is not None else None
        if in_memory and state is not None:
            raise ValueError("An in-memory device cannot have a state directory")
        if initial_state is not None and not in_memory:
            raise ValueError("Restore snapshots into an in-memory device")
        self._state = None if in_memory else (Path(state) if state is not None else _new_device_directory()).expanduser().resolve()
        self._library = library if isinstance(library, Library) else Library(library)
        metadata = (dict(iphone_model=model, ios_version=os_version, ios_build=os_build)
                    if platform == "iphone" else
                    dict(mac_model=model, macos_version=os_version, macos_build=os_build))
        if initial_state is not None:
            from .crypto import _decode
            initial_state = _decode(initial_state, self._encryption_key, self._library)
        self._client = self._library.client(self._state, initial_state=initial_state, device_platform=platform, **metadata,
            serial_number=serial_number, user_agent=user_agent, client_info=client_info, headers=headers,
            transport=transport, clock=clock)
        try:
            data = self._client.device_info
            self._info = DeviceInfo(platform=data["platform"], model=data.get("model"),
                os_version=data.get("os_version"), os_build=data.get("os_build"),
                serial_number=None if data["serial_number"] in (None, "", "0") else data["serial_number"])
        except BaseException:
            self._client.close()
            raise
        self._session: Session | None = None
        self._store_session: StoreSession | None = None

    @classmethod
    def memory(cls, *, initial_state: bytes | None = None, platform: str | None = None, **options) -> Device:
        """Keep identity/ADI in RAM; optionally restore a serialized snapshot."""
        return cls(in_memory=True, initial_state=initial_state,
                   platform=platform if platform is not None else ("mac" if initial_state is None else None),
                   **options)

    @classmethod
    def mac(cls, state: str | os.PathLike | None = None, *, model: str | None = None,
            macos: str | None = None, build: str | None = None,
            serial_number: str | None = None, **options) -> Device:
        """Create/reopen Mac ADI. Extra options accept library, transport and clock."""
        return cls(state, platform="mac", model=model, os_version=macos, os_build=build,
                   serial_number=serial_number, **options)

    @classmethod
    def iphone(cls, state: str | os.PathLike | None = None, *, model: str | None = None,
               ios: str | None = None, build: str | None = None,
               serial_number: str | None = None, **options) -> Device:
        """Create/reopen an iPhone identity backed by Mac ADI (platform 1)."""
        return cls(state, platform="iphone", model=model, os_version=ios, os_build=build,
                   serial_number=serial_number, **options)

    @classmethod
    def windows(cls, state: str | os.PathLike | None = None, *,
                serial_number: str | None = None, **options) -> Device:
        """Create/reopen Windows ADI, independently of the host operating system."""
        return cls(state, platform="windows", serial_number=serial_number, **options)

    @classmethod
    def android(cls, state: str | os.PathLike | None = None, **options) -> Device:
        """Create/reopen an Android identity backed by native ADI (platform 4)."""
        return cls(state, platform="android", **options)

    @classmethod
    def open(cls, state: str | os.PathLike, **options) -> Device:
        """Reopen saved identity without repeating its platform or metadata."""
        path = Path(state).expanduser().resolve()
        if not (path / "identity.json").is_file():
            raise FileNotFoundError(f"No saved device in {path}")
        return cls(path, **options)

    @property
    def state(self) -> Path | None:
        return self._state

    @property
    def info(self) -> DeviceInfo:
        return self._info

    @property
    def session(self) -> Session | None:
        """Last saved session. Loading it does not check token expiry with Apple."""
        if self._session is None:
            data = self._client.session_data()
            if data:
                from .crypto import _decode
                path = self.state / "account-session.plist" if self.state is not None else None
                self._session = Session._decode(_decode(data, self._encryption_key, self._library), path)
        return self._session

    def provision(self) -> Device:
        """Prepare the ADI profile explicitly; normal usage does this automatically."""
        self._client.provision()
        return self

    @property
    def store_session(self) -> StoreSession | None:
        if self._store_session is None or not self._store_session._handle:
            data = self._client.session_data(kind="store")
            if data:
                self._store_session = StoreSession.deserialize(data, encryption_key=self._encryption_key,
                                                               library=self._library)
                if self.state is not None:
                    self._store_session._path = self.state / "store-account-session.plist"
        return self._store_session

    def provision_store(self) -> Device:
        self._client.provision_store()
        return self

    def store_headers(self) -> dict[str, str]:
        return self._client.store_headers()

    def login_store(self, *, email: str, password: str | None = None,
                    two_factor: Callable[[], str] | None = None) -> StoreSession:
        self.provision_store()
        if password is None:
            password = getpass.getpass("Apple ID password: ")
        if two_factor is None:
            two_factor = lambda: input("Apple ID verification code: ").strip()
        try:
            session = self._client.login_store(email, password, two_factor)
            try:
                self._client.set_session_data(session.serialize(encryption_key=self._encryption_key), kind="store")
                if self.state is not None:
                    session._path = self.state / "store-account-session.plist"
                    session._encryption_key = self._encryption_key
            except BaseException:
                session.close()
                raise
            if self._store_session is not None:
                self._store_session.close()
            self._store_session = session
            return session
        finally:
            password = ""

    def store_request(self, url: str, *, method: str = "GET", body: bytes = b"",
                      headers: dict[str, str] | None = None, session: StoreSession | None = None) -> HttpResponse:
        session = session or self.store_session
        if session is None:
            raise RuntimeError("No Store session; use login_store() first")
        response = self._client.store_request(session, HttpRequest(url, method, headers or {}, body))
        if session._path is not None:
            key = session._encryption_key if session._encryption_key is not None else self._encryption_key
            session.save(session._path, encryption_key=key)
        elif session is self._store_session:
            self._client.set_session_data(session.serialize(encryption_key=self._encryption_key), kind="store")
        return response

    def login_store_with_pet(self, *, email: str, account: Session | None = None) -> StoreSession:
        """Mac Accounts login. Uses an existing PET; caller saves/closes the Store session."""
        account = account or self.session
        if account is None:
            raise RuntimeError("No account session; use login() first")
        with AccountSession.from_plist(account.plist(), library=self._client._library) as native:
            return self._client.login_store_with_pet(email, native)

    def developer_session(self, account: Session | None = None) -> dict:
        account = account or self.session
        if account is None:
            raise RuntimeError("No account session; use login() first")
        with AccountSession.from_plist(account.plist(), library=self._client._library) as native:
            return self._client.developer_session(native)

    def developer_headers(self, session: dict) -> dict[str, str]:
        return self._client.developer_headers(session)

    def headers(self) -> dict[str, str]:
        """Fresh anisette headers as a normal mapping, ready for an HTTP library."""
        return self._client.headers()

    def login(self, *, email: str, password: str | None = None,
              two_factor: Callable[[], str] | None = None,
              verification: Verification | None = None) -> Session:
        """Log in and save the session. Missing password/2FA callbacks prompt locally."""
        options = _verification(two_factor, verification)
        prompt = "SMS verification code: " if options.method == "sms" else "Apple ID verification code: "
        options = replace(options, code=options.code or (lambda: input(prompt).strip()),
                          select_phone=options.select_phone or _prompt_phone)
        self.provision()
        if password is None:
            password = getpass.getpass("Apple ID password: ")
        try:
            with self._client.login(email, password, verification=options) as native_session:
                path = self.state / "account-session.plist" if self.state is not None else None
                session = Session._decode(native_session.plist(), path)
                self._client.set_session_data(native_session.serialize(encryption_key=self._encryption_key))
                self._session = session
                return session
        finally:
            password = ""

    def serialize_state(self) -> bytes:
        """Snapshot identity, ADI, Store provisioning and auto-saved account bytes."""
        return self._client.serialize_state(encryption_key=self._encryption_key)

    def close(self):
        self._client.close()
        if self._store_session is not None:
            self._store_session.close()

    def __enter__(self) -> Device:
        self._client.__enter__()
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self) -> str:
        return f"Device(info={self.info!r}, state={str(self.state)!r})"


