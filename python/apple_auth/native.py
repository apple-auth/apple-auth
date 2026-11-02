"""Native library discovery, C ABI bindings and explicit handle owners."""
from __future__ import annotations

import ctypes as c
import base64
import json
import inspect
import os
from pathlib import Path
import sys
import sysconfig
from typing import Callable
from urllib.parse import urlsplit

from .models import DeviceInfo, HttpRequest, HttpResponse, HttpTiming, TrustedPhoneNumber, Verification, _verification

DEVICE_PLATFORMS = ("windows", "mac", "iphone", "android")
_PLATFORM_IDS = {name: index for index, name in enumerate(DEVICE_PLATFORMS, 1)}


class NativeError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class _Buffer(c.Structure):
    _fields_ = [("data", c.POINTER(c.c_uint8)), ("size", c.c_size_t)]


class _Request(c.Structure):
    _fields_ = [("url", c.c_char_p), ("method", c.c_char_p),
                ("headers_json", c.c_char_p), ("body", c.POINTER(c.c_uint8)),
                ("body_size", c.c_size_t)]


class _Response(c.Structure):
    _fields_ = [("status", c.c_long), ("body", _Buffer), ("headers_json", _Buffer)]


_Transport = c.CFUNCTYPE(c.c_int, c.c_void_p, c.POINTER(_Request), c.POINTER(_Response))
_Observer = c.CFUNCTYPE(None, c.c_void_p, c.c_char_p, c.c_char_p, c.c_long, c.c_double)
_Clock = c.CFUNCTYPE(c.c_int64, c.c_void_p)
_TwoFactor = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t))
_PhoneSelection = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_char_p, c.POINTER(c.c_int64))


class _Options(c.Structure):
    _fields_ = [("transport", _Transport), ("observer", _Observer),
                ("clock", _Clock), ("context", c.c_void_p)]


class _MacDevice(c.Structure):
    _fields_ = [("model", c.c_char_p), ("macos_version", c.c_char_p), ("macos_build", c.c_char_p)]


class _IPhoneDevice(c.Structure):
    _fields_ = [("model", c.c_char_p), ("ios_version", c.c_char_p), ("ios_build", c.c_char_p)]


class _DeviceHeaders(c.Structure):
    _fields_ = [("user_agent", c.c_char_p), ("client_info", c.c_char_p)]


class _ClientConfig(c.Structure):
    _fields_ = [("directory", c.c_char_p), ("options", c.POINTER(_Options)),
                ("platform", c.c_int), ("mac_device", c.POINTER(_MacDevice)),
                ("iphone_device", c.POINTER(_IPhoneDevice)), ("serial_number", c.c_char_p),
                ("headers", c.POINTER(_DeviceHeaders)), ("headers_json", c.c_char_p),
                ("state", c.POINTER(c.c_uint8)), ("state_size", c.c_size_t)]


class _VerificationOptions(c.Structure):
    _fields_ = [("method", c.c_int), ("phone_number_id", c.c_int64),
                ("code", _TwoFactor), ("select_phone", _PhoneSelection), ("context", c.c_void_p)]


def _utf8(value: str, field_name: str) -> bytes:
    if "\0" in value:
        raise ValueError(f"{field_name} contains a NUL character")
    return value.encode("utf-8")


def _path(value: str | os.PathLike) -> bytes:
    return _utf8(os.fsdecode(value), "Path")


def find_library() -> Path:
    explicit = os.environ.get("APPLE_AUTH_LIBRARY")
    if explicit:
        return Path(explicit).expanduser().resolve()
    project = Path(__file__).resolve().parents[2]
    name = "apple_auth_client.dll" if sys.platform == "win32" else (
        "libapple_auth_client.dylib" if sys.platform == "darwin" else "libapple_auth_client.so")
    directories = ["build/windows/Release", "build/release", "build/macos", "build/linux", "build/debug",
                   "build/windows/Debug", "install/bin", "install/lib", "install/lib64"]
    for directory in directories:
        candidate = project / directory / name
        if candidate.is_file():
            return candidate
    if project.parent.name == "share":
        prefix = project.parent.parent
        for directory in ("bin", "lib", "lib64", f"lib/{sysconfig.get_config_var('MULTIARCH') or ''}"):
            candidate = prefix / directory / name
            if candidate.is_file():
                return candidate
    for prefix in dict.fromkeys((Path(sys.prefix), Path(sys.base_prefix))):
        for directory in ("bin", "lib", "lib64", f"lib/{sysconfig.get_config_var('MULTIARCH') or ''}"):
            candidate = prefix / directory / name
            if candidate.is_file():
                return candidate
    raise FileNotFoundError("Build apple-auth with APPLE_AUTH_WITH_CLIENT=ON and "
                            "BUILD_SHARED_LIBS=ON, or pass the client library path explicitly")


def _dependency_directories(library: Path, supplied) -> list[Path]:
    directories = [library.parent, *(Path(path).expanduser().resolve() for path in supplied)]
    directories += [Path(path) for path in os.environ.get("APPLE_AUTH_DLL_DIRS", "").split(os.pathsep) if path]
    for parent in list(library.parents)[:3]:
        cache = parent / "CMakeCache.txt"
        if not cache.is_file():
            continue
        values = {}
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            if line and not line.startswith(("#", "//")) and "=" in line:
                key, value = line.split("=", 1)
                values[key.split(":", 1)[0]] = value
        prefixes = values.get("CMAKE_PREFIX_PATH", "").split(";")
        if values.get("VCPKG_INSTALLED_DIR") and values.get("VCPKG_TARGET_TRIPLET"):
            prefixes.append(str(Path(values["VCPKG_INSTALLED_DIR"]) / values["VCPKG_TARGET_TRIPLET"]))
        for prefix in filter(None, prefixes):
            directories.append(Path(prefix) / ("debug/bin" if library.parent.name == "Debug" else "bin"))
    return list(dict.fromkeys(path.resolve() for path in directories if path.is_dir()))


class Library:
    def __init__(self, path: str | os.PathLike | None = None, *, dll_directories=()):
        self.path = Path(path).expanduser().resolve() if path is not None else find_library()
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        self.dependency_directories = _dependency_directories(self.path, dll_directories)
        self._dll_directories = [os.add_dll_directory(str(path)) for path in self.dependency_directories] if sys.platform == "win32" else []
        try:
            self._native = c.CDLL(str(self.path))
        except OSError as error:
            raise OSError(f"Cannot load {self.path.name}; add dependency directories with "
                          "dll_directories/--dll-dir or APPLE_AUTH_DLL_DIRS") from error
        handle = c.c_void_p
        shapes = {
            "aauth_client_create": [c.POINTER(_ClientConfig), c.POINTER(handle)],
            "aauth_client_state": [handle, c.POINTER(_Buffer)],
            "aauth_client_session_data": [handle, c.c_int, c.POINTER(_Buffer)],
            "aauth_client_set_session_data": [handle, c.c_int, c.POINTER(c.c_uint8), c.c_size_t],
            "aauth_client_device_platform": [handle, c.POINTER(c.c_int)],
            "aauth_client_mac_device": [handle, c.POINTER(_Buffer)],
            "aauth_client_device_info": [handle, c.POINTER(_Buffer)],
            "aauth_client_provision": [handle],
            "aauth_client_headers": [handle, c.POINTER(_Buffer)],
            "aauth_client_login": [handle, c.c_char_p, c.c_char_p, c.POINTER(_VerificationOptions), c.POINTER(handle)],
            "aauth_account_session_save": [handle, c.c_char_p],
            "aauth_account_session_plist": [handle, c.POINTER(_Buffer)],
            "aauth_client_buffer_alloc": [c.c_size_t, c.POINTER(_Buffer)],
            "aauth_client_store_provision": [handle],
            "aauth_client_store_headers": [handle, c.POINTER(_Buffer)],
            "aauth_client_store_login": [handle, c.c_char_p, c.c_char_p, _TwoFactor, handle, c.POINTER(handle)],
            "aauth_store_session_load": [c.c_char_p, c.POINTER(handle)],
            "aauth_store_session_from_plist": [c.POINTER(c.c_uint8), c.c_size_t, c.POINTER(handle)],
            "aauth_store_session_save": [handle, c.c_char_p],
            "aauth_store_session_plist": [handle, c.POINTER(_Buffer)],
            "aauth_store_session_info": [handle, c.POINTER(_Buffer)],
            "aauth_store_session_headers": [handle, c.c_char_p, c.POINTER(_Buffer)],
            "aauth_client_store_request": [handle, handle, c.POINTER(_Request), c.POINTER(_Buffer)],
        }
        try:
            for name, arguments in shapes.items():
                function = getattr(self._native, name)
                function.argtypes, function.restype = arguments, c.c_int
            for name in ("aauth_client_free", "aauth_account_session_free", "aauth_store_session_free"):
                function = getattr(self._native, name)
                function.argtypes, function.restype = [handle], None
            self._native.aauth_client_buffer_free.argtypes = [c.POINTER(_Buffer)]
            self._native.aauth_client_buffer_free.restype = None
            for name in ("aauth_client_version", "aauth_client_last_error"):
                function = getattr(self._native, name)
                function.argtypes, function.restype = [], c.c_char_p
        except AttributeError as error:
            raise RuntimeError("Rebuild the client library: this binary predates the current Python/client C API") from error
        self._bind_extended()

    def _bind_extended(self):
        handle, buffer = c.c_void_p, c.POINTER(_Buffer)
        data, size, text = c.POINTER(c.c_uint8), c.c_size_t, c.c_char_p
        result = c.POINTER(handle)
        options = c.POINTER(_Options)
        headers = c.POINTER(_DeviceHeaders)
        shapes = {
            "aauth_client_features": [buffer],
            "aauth_client_generate_session_key": [buffer],
            "aauth_client_encrypt_session": [data, size, data, size, buffer],
            "aauth_client_decrypt_session": [data, size, data, size, buffer],
            "aauth_client_save_session": [text, data, size],
            "aauth_account_session_from_plist": [data, size, result],
            "aauth_client_developer_session": [handle, handle, buffer],
            "aauth_client_developer_headers": [handle, text, text, c.c_int64, buffer],
            "aauth_store_client_create": [text, c.c_int, options, headers, text, result],
            "aauth_store_client_provision": [handle],
            "aauth_store_client_headers": [handle, buffer],
            "aauth_store_client_login": [handle, text, text, _TwoFactor, handle, result],
            "aauth_client_store_login_with_pet": [handle, text, handle, result],
            "aauth_store_client_login_with_pet": [handle, text, handle, handle, result],
            "aauth_store_client_request": [handle, handle, c.POINTER(_Request), buffer],
            "aauth_store_session_ios_context": [handle, text, buffer],
            "aauth_store_session_testflight_context": [handle, data, size, text, buffer],
            "aauth_testflight_client_create": [data, size, options, text, result],
            "aauth_testflight_client_from_store_cookies": [data, size, options, text, result],
            "aauth_testflight_client_save": [handle, text],
            "aauth_testflight_client_serialize": [handle, buffer],
            "aauth_testflight_client_catalog": [handle, buffer],
            "aauth_testflight_client_install_metadata": [handle, text, buffer],
            "aauth_testflight_client_download_ipa": [handle, text, text, c.c_int, buffer],
            "aauth_appstore_ios_client_create": [data, size, options, text, result],
            "aauth_appstore_ios_client_download_ipa": [handle, c.c_uint64, text, c.c_int, buffer],
            "aauth_appstore_mac_client_create": [handle, text, text, options, headers, text, result],
            "aauth_appstore_mac_client_download": [handle, c.c_uint64, text, c.c_int, buffer],
            "aauth_generate_kbsync": [c.c_uint64, data, size, data, size, buffer],
            "aauth_unwrap_testflight_transport": [text, text, data, size, data, size, buffer],
            "aauth_normalize_testflight_ipa": [text, text, text, buffer],
            "aauth_unwrap_appstore_mac_package": [text, text, data, size, data, size, buffer],
        }
        for kind in ("ios", "mac"):
            for operation in ("catalog", "metadata", "offer") + (("acquire_free",) if kind == "ios" else ()):
                shapes[f"aauth_appstore_{kind}_client_{operation}"] = [handle, c.c_uint64, buffer]
        for name, arguments in shapes.items():
            function = getattr(self._native, name, None)
            if function is not None:
                function.argtypes, function.restype = arguments, c.c_int
        for kind in ("store", "testflight", "appstore_ios", "appstore_mac"):
            function = getattr(self._native, f"aauth_{kind}_client_free", None)
            if function is not None:
                function.argtypes, function.restype = [handle], None

    def _function(self, name):
        function = getattr(self._native, name, None)
        if function is None:
            raise RuntimeError(f"Rebuild the native library to use {name}")
        return function

    @property
    def features(self) -> dict[str, bool]:
        function = getattr(self._native, "aauth_client_features", None)
        return json.loads(self._buffer(function)) if function else {"store_protocols": False, "downloads": False}

    @property
    def version(self) -> str:
        return self._native.aauth_client_version().decode("utf-8")

    def _check(self, status: int):
        if status:
            raise NativeError(status, self._native.aauth_client_last_error().decode("utf-8", "replace"))

    def _buffer(self, function, *arguments, check=None) -> bytes:
        output = _Buffer()
        try:
            (check or self._check)(function(*arguments, c.byref(output)))
            return c.string_at(output.data, output.size) if output.size else b""
        finally:
            self._native.aauth_client_buffer_free(c.byref(output))

    def client(self, directory=None, *, initial_state: bytes | None = None, device_platform: str | None = None,
               mac_model: str | None = None, macos_version: str | None = None,
               macos_build: str | None = None, serial_number: str | None = None,
               iphone_model: str | None = None, ios_version: str | None = None,
               ios_build: str | None = None, user_agent: str | None = None,
               client_info: str | None = None,
               headers: dict[str, str] | None = None,
               transport=None, clock=None) -> Client:
        """Use a synthetic identity. None reuses saved platform; new state defaults to Windows."""
        return Client(self, directory, initial_state=initial_state, device_platform=device_platform, mac_model=mac_model,
                      macos_version=macos_version, macos_build=macos_build, serial_number=serial_number,
                      iphone_model=iphone_model, ios_version=ios_version, ios_build=ios_build,
                      user_agent=user_agent, client_info=client_info,
                      headers=headers,
                      transport=transport, clock=clock)


class _NativeClient:
    _free_name = "aauth_client_free"

    def _init_callbacks(self, library, transport=None, clock=None):
        self._library = library
        self._handle = c.c_void_p()
        self._callback_error = None
        self.http_timings = []
        def remember(error):
            if self._callback_error is None:
                self._callback_error = error

        def send(_context, request, output):
            try:
                raw = request.contents
                result = transport(HttpRequest(raw.url.decode("utf-8"), raw.method.decode("ascii"),
                    json.loads(raw.headers_json), c.string_at(raw.body, raw.body_size) if raw.body_size else b""))
                body = bytes(result.body)
                library._check(library._native.aauth_client_buffer_alloc(len(body), c.byref(output.contents.body)))
                if body:
                    c.memmove(output.contents.body.data, body, len(body))
                output.contents.status = result.status
                pairs = list(result.headers.items()) if isinstance(result.headers, dict) else list(result.headers)
                encoded = json.dumps(pairs).encode("utf-8")
                library._check(library._native.aauth_client_buffer_alloc(len(encoded), c.byref(output.contents.headers_json)))
                if encoded:
                    c.memmove(output.contents.headers_json.data, encoded, len(encoded))
                return 0
            except BaseException as error:
                remember(error)
                return -1

        def observe(_context, method, url, status, seconds):
            try:
                parts = urlsplit(url.decode("utf-8"))
                self.http_timings.append(HttpTiming(method.decode("ascii"), parts.hostname or "",
                                                    parts.path, status, seconds))
            except BaseException as error:
                remember(error)

        def current_time(_context):
            try:
                value = int(clock())
                if not -(2**63) <= value < 2**63:
                    raise ValueError("Clock exceeds the signed 64-bit range")
                return value
            except BaseException as error:
                remember(error)
                return -1

        self._callbacks = (_Transport(send) if transport else _Transport(),
                           _Observer(observe), _Clock(current_time) if clock else _Clock())

    def _prepare(self):
        if not self._handle:
            raise RuntimeError("Client is closed")
        self._callback_error = None

    def _check(self, status):
        if self._callback_error is not None:
            error, self._callback_error = self._callback_error, None
            raise error
        self._library._check(status)

    def close(self):
        if self._handle:
            self._library._function(self._free_name)(self._handle)
            self._handle = c.c_void_p()
        self._callbacks = ()
        self._options = None

    def __enter__(self):
        self._prepare()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class Client(_NativeClient):
    def __init__(self, library: Library, directory=None, *,
                 initial_state: bytes | None = None, device_platform: str | None = None,
                 mac_model: str | None = None,
                 macos_version: str | None = None,
                 macos_build: str | None = None,
                 serial_number: str | None = None,
                 iphone_model: str | None = None, ios_version: str | None = None,
                 ios_build: str | None = None,
                 user_agent: str | None = None, client_info: str | None = None,
                 headers: dict[str, str] | None = None,
                 transport: Callable[[HttpRequest], HttpResponse] | None = None,
                 clock: Callable[[], int] | None = None):
        self._library = library
        self._handle = c.c_void_p()
        self._callback_error: BaseException | None = None
        self.http_timings: list[HttpTiming] = []
        if device_platform is not None and device_platform not in _PLATFORM_IDS:
            raise ValueError(f"device_platform must be one of: {', '.join(DEVICE_PLATFORMS)}")

        self._init_callbacks(library, transport, clock)
        options = _Options(*self._callbacks, None)
        try:
            mac_device = _MacDevice(
                _utf8(mac_model, "mac_model") if mac_model is not None else None,
                _utf8(macos_version, "macos_version") if macos_version is not None else None,
                _utf8(macos_build, "macos_build") if macos_build is not None else None)
            iphone_device = _IPhoneDevice(
                _utf8(iphone_model, "iphone_model") if iphone_model is not None else None,
                _utf8(ios_version, "ios_version") if ios_version is not None else None,
                _utf8(ios_build, "ios_build") if ios_build is not None else None)
            iphone = c.pointer(iphone_device) if any(
                value is not None for value in (iphone_model, ios_version, ios_build)) else None
            if headers is not None and (not isinstance(headers, dict) or not all(
                isinstance(name, str) and isinstance(value, str) for name, value in headers.items())):
                raise TypeError("headers must map strings to strings")
            overrides = _DeviceHeaders(
                _utf8(user_agent, "user_agent") if user_agent is not None else None,
                _utf8(client_info, "client_info") if client_info is not None else None)
            state = None if initial_state is None else bytes(initial_state)
            state_buffer = None if state is None else (c.c_uint8 * len(state)).from_buffer_copy(state)
            config = _ClientConfig(
                _path(directory) if directory is not None else None, c.pointer(options),
                _PLATFORM_IDS.get(device_platform, 0), c.pointer(mac_device), iphone,
                _utf8(serial_number, "serial_number") if serial_number is not None else None,
                c.pointer(overrides), json.dumps(headers).encode("utf-8") if headers is not None else None,
                state_buffer, len(state) if state is not None else 0)
            self._check(library._native.aauth_client_create(c.byref(config), c.byref(self._handle)))
        except BaseException:
            self.close()
            raise

    def serialize_state(self, *, encryption_key: bytes | None = None) -> bytes:
        self._prepare()
        data = self._library._buffer(self._library._native.aauth_client_state, self._handle, check=self._check)
        if encryption_key is not None:
            from .crypto import encrypt
            return encrypt(data, encryption_key, library=self._library)
        return data

    def session_data(self, *, kind="account") -> bytes:
        self._prepare()
        return self._library._buffer(self._library._native.aauth_client_session_data,
                                     self._handle, ("account", "store").index(kind), check=self._check)

    def set_session_data(self, data: bytes, *, kind="account"):
        self._prepare()
        data = bytes(data)
        buffer = (c.c_uint8 * len(data)).from_buffer_copy(data)
        self._check(self._library._native.aauth_client_set_session_data(self._handle, ("account", "store").index(kind), buffer, len(data)))

    def provision(self):
        self._prepare()
        self._check(self._library._native.aauth_client_provision(self._handle))

    @property
    def device_platform(self) -> str:
        self._prepare()
        value = c.c_int()
        self._check(self._library._native.aauth_client_device_platform(self._handle, c.byref(value)))
        return DEVICE_PLATFORMS[value.value - 1]

    @property
    def mac_device(self) -> dict[str, str] | None:
        self._prepare()
        value = self._library._buffer(self._library._native.aauth_client_mac_device,
                                     self._handle, check=self._check)
        return json.loads(value)

    @property
    def device_info(self) -> dict:
        self._prepare()
        value = self._library._buffer(self._library._native.aauth_client_device_info,
                                     self._handle, check=self._check)
        return json.loads(value)

    def headers(self) -> dict[str, str]:
        self._prepare()
        value = self._library._buffer(self._library._native.aauth_client_headers,
                                     self._handle, check=self._check)
        return json.loads(value)

    def login(self, email: str, password: str, two_factor: Callable[[], str] | None = None,
              *, verification: Verification | None = None) -> AccountSession:
        return self._login(email, password, two_factor, store=False, verification=verification)

    def login_store(self, email: str, password: str, two_factor: Callable[[], str] | None = None) -> StoreSession:
        return self._login(email, password, two_factor, store=True)

    def login_store_with_pet(self, email: str, account: AccountSession) -> StoreSession:
        self._prepare()
        account._require_open()
        if account._library is not self._library:
            raise ValueError("Account and client must use the same Library")
        result = c.c_void_p()
        function = self._library._function("aauth_client_store_login_with_pet")
        try:
            self._check(function(self._handle, _utf8(email, "Apple ID"), account._handle, c.byref(result)))
            return StoreSession(self._library, result)
        except BaseException:
            if result:
                self._library._native.aauth_store_session_free(result)
            raise

    def developer_session(self, account: AccountSession) -> dict:
        self._prepare()
        account._require_open()
        if account._library is not self._library:
            raise ValueError("Account and client must use the same Library")
        return json.loads(self._library._buffer(self._library._function("aauth_client_developer_session"),
            self._handle, account._handle, check=self._check))

    def developer_headers(self, session: dict) -> dict[str, str]:
        self._prepare()
        return json.loads(self._library._buffer(self._library._function("aauth_client_developer_headers"),
            self._handle, _utf8(session["account_id"], "Account ID"), _utf8(session["token"], "Token"),
            session["expires_at_ms"], check=self._check))

    def _login(self, email, password, two_factor, *, store, verification=None):
        self._prepare()
        selected = None if store else _verification(two_factor, verification)
        code_callback = two_factor if store else selected.code

        def verify(_context, output, capacity, written):
            try:
                value = code_callback()
                if inspect.isawaitable(value):
                    if inspect.iscoroutine(value): value.close()
                    raise TypeError("Use AsyncDevice for async verification callbacks")
                if not isinstance(value, str):
                    raise TypeError("Verification code callback must return a string")
                code = value.encode("ascii")
                if len(code) > capacity:
                    raise ValueError("Verification code exceeds the callback buffer")
                c.memmove(output, code, len(code))
                written[0] = len(code)
                return 0
            except BaseException as error:
                self._callback_error = error
                return -1

        def choose(_context, phones_json, output):
            try:
                fields = json.loads(phones_json.decode("utf-8"))
                phones = tuple(TrustedPhoneNumber(id=value["id"], display_number=value["display_number"])
                               for value in fields)
                phone_id = selected.select_phone(phones)
                if inspect.isawaitable(phone_id):
                    if inspect.iscoroutine(phone_id): phone_id.close()
                    raise TypeError("Use AsyncDevice for async phone selection")
                if type(phone_id) is not int or not 0 < phone_id < 2**63:
                    raise ValueError("Phone selection must return a positive Apple phone ID")
                output[0] = phone_id
                return 0
            except BaseException as error:
                self._callback_error = error
                return -1

        callback = _TwoFactor(verify) if code_callback else _TwoFactor()
        phone_callback = _PhoneSelection(choose) if selected and selected.select_phone else _PhoneSelection()
        result = c.c_void_p()
        try:
            if store:
                status = self._library._native.aauth_client_store_login(self._handle, _utf8(email, "Apple ID"),
                    _utf8(password, "Password"), callback, None, c.byref(result))
            else:
                verification = _VerificationOptions(
                    ("automatic", "trusted_device", "sms").index(selected.method),
                    selected.phone_number_id, callback, phone_callback, None)
                status = self._library._native.aauth_client_login(self._handle, _utf8(email, "Apple ID"),
                    _utf8(password, "Password"), c.byref(verification), c.byref(result))
            self._check(status)
            return StoreSession(self._library, result) if store else AccountSession(self._library, result)
        except BaseException:
            if result:
                free = self._library._native.aauth_store_session_free if store else self._library._native.aauth_account_session_free
                free(result)
            raise

    def provision_store(self):
        self._prepare()
        self._check(self._library._native.aauth_client_store_provision(self._handle))

    def store_headers(self) -> dict[str, str]:
        self._prepare()
        return json.loads(self._library._buffer(self._library._native.aauth_client_store_headers,
                                               self._handle, check=self._check))

    def store_request(self, session: StoreSession, request: HttpRequest) -> HttpResponse:
        self._prepare()
        session._require_open()
        if session._library is not self._library:
            raise ValueError("Store session and client must use the same Library")
        body = bytes(request.body)
        buffer = (c.c_uint8 * len(body)).from_buffer_copy(body)
        raw = _Request(_utf8(request.url, "URL"), _utf8(request.method, "Method"),
                       json.dumps(request.headers).encode("utf-8"), buffer, len(body))
        value = json.loads(self._library._buffer(self._library._native.aauth_client_store_request,
            self._handle, session._handle, c.byref(raw), check=self._check))
        return HttpResponse(value["status"], base64.b64decode(value["body"], validate=True),
                            tuple(tuple(pair) for pair in value["headers"]))



class AccountSession:
    def __init__(self, library: Library, handle):
        self._library, self._handle = library, handle

    @classmethod
    def from_plist(cls, data: bytes, *, library: Library | None = None) -> AccountSession:
        library = library or Library()
        raw = (c.c_uint8 * len(data)).from_buffer_copy(data)
        handle = c.c_void_p()
        library._check(library._function("aauth_account_session_from_plist")(raw, len(data), c.byref(handle)))
        return cls(library, handle)

    @classmethod
    def load(cls, filename, *, encryption_key=None, library: Library | None = None) -> AccountSession:
        from .crypto import _read
        return cls.deserialize(_read(filename), encryption_key=encryption_key, library=library)

    @classmethod
    def deserialize(cls, data: bytes, *, encryption_key=None, library=None) -> AccountSession:
        from .crypto import _decode, _library
        lib = _library(library)
        return cls.from_plist(_decode(data, encryption_key, lib), library=lib)

    def serialize(self, *, encryption_key=None) -> bytes:
        from .crypto import _encode
        return _encode(self.plist(), encryption_key, self._library)

    def _require_open(self):
        if not self._handle:
            raise RuntimeError("Account session is closed")

    def save(self, filename, *, encryption_key=None):
        self._require_open()
        if encryption_key is not None:
            from .crypto import _save
            _save(filename, self.plist(), encryption_key, self._library)
            return
        self._library._check(self._library._native.aauth_account_session_save(self._handle, _path(filename)))

    def plist(self) -> bytes:
        self._require_open()
        return self._library._buffer(self._library._native.aauth_account_session_plist, self._handle)

    def close(self):
        if self._handle:
            self._library._native.aauth_account_session_free(self._handle)
            self._handle = c.c_void_p()

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class StoreSession:
    """Store credentials and cookies, separate from the GrandSlam Session.

    Keep this object and saved files private. Reopening does not check expiry.
    Use Device.store_request() to add fresh anisette and SAP automatically.
    """
    def __init__(self, library: Library, handle):
        self._library, self._handle = library, handle
        self._path: Path | None = None
        self._encryption_key: bytes | None = None

    @classmethod
    def from_plist(cls, data: bytes, *, library: Library | None = None) -> StoreSession:
        library = library or Library()
        raw = (c.c_uint8 * len(data)).from_buffer_copy(data)
        handle = c.c_void_p()
        library._check(library._native.aauth_store_session_from_plist(raw, len(data), c.byref(handle)))
        return cls(library, handle)

    @classmethod
    def load(cls, filename, *, encryption_key=None, library: Library | None = None) -> StoreSession:
        library = library or Library()
        if encryption_key is not None:
            from .crypto import _read
            result = cls.deserialize(_read(filename), encryption_key=encryption_key, library=library)
            result._path = Path(filename).expanduser().resolve()
            return result
        handle = c.c_void_p()
        library._check(library._native.aauth_store_session_load(_path(filename), c.byref(handle)))
        result = cls(library, handle)
        result._path = Path(filename).expanduser().resolve()
        return result

    @classmethod
    def deserialize(cls, data: bytes, *, encryption_key=None, library=None) -> StoreSession:
        from .crypto import _decode, _key, _library
        lib = _library(library)
        result = cls.from_plist(_decode(data, encryption_key, lib), library=lib)
        result._encryption_key = _key(encryption_key) if encryption_key is not None else None
        return result

    def serialize(self, *, encryption_key=None) -> bytes:
        from .crypto import _encode
        return _encode(self.plist(), encryption_key, self._library)

    def _require_open(self):
        if not self._handle:
            raise RuntimeError("Store session is closed")

    def _info(self):
        self._require_open()
        return json.loads(self._library._buffer(self._library._native.aauth_store_session_info, self._handle))

    @property
    def account_id(self) -> str:
        return self._info()["account_id"]

    @property
    def storefront(self) -> str:
        return self._info()["storefront"]

    @property
    def protocol(self) -> str:
        return ("android_music", "macos_accounts", "configurator")[self._info().get("protocol", 0)]

    def ios_context(self, country: str) -> bytes:
        self._require_open()
        return self._library._buffer(self._library._function("aauth_store_session_ios_context"),
                                    self._handle, _utf8(country, "Country"))

    def testflight_context(self, hardware20: bytes, headers: dict[str, str]) -> bytes:
        self._require_open()
        hardware = (c.c_uint8 * len(hardware20)).from_buffer_copy(hardware20)
        return self._library._buffer(self._library._function("aauth_store_session_testflight_context"),
            self._handle, hardware, len(hardware20), json.dumps(headers).encode("utf-8"))

    def plist(self) -> bytes:
        self._require_open()
        return self._library._buffer(self._library._native.aauth_store_session_plist, self._handle)

    def headers(self, url: str) -> dict[str, str]:
        """Authentication/cookies for an iTunes HTTPS URL; fresh anisette is separate."""
        self._require_open()
        return json.loads(self._library._buffer(self._library._native.aauth_store_session_headers,
                                               self._handle, _utf8(url, "URL")))

    def save(self, filename, *, encryption_key=None) -> Path:
        self._require_open()
        if encryption_key is not None:
            from .crypto import _save
            _save(filename, self.plist(), encryption_key, self._library)
        else:
            self._library._check(self._library._native.aauth_store_session_save(self._handle, _path(filename)))
        self._path = Path(filename).expanduser().resolve()
        self._encryption_key = bytes(encryption_key) if encryption_key is not None else None
        return self._path

    def close(self):
        if self._handle:
            self._library._native.aauth_store_session_free(self._handle)
            self._handle = c.c_void_p()

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        try:
            self.close()
        except (AttributeError, TypeError):
            pass

    def __repr__(self):
        return f"StoreSession(path={str(self._path)!r}, closed={not bool(self._handle)})"


