"""Store protocols and optional TestFlight/App Store clients backed by the C++ SDK.

Calls are synchronous; serialize operations on each client. Contexts/catalogs and
metadata use bytes, download operations return metadata dictionaries. Use
asyncio.to_thread for standalone clients in async applications.
"""
from __future__ import annotations

import base64
import ctypes as c
import getpass
import json
from pathlib import Path

from .models import HttpResponse
from .native import (AccountSession, Client, Library, StoreSession, _NativeClient,
                     _Options, _DeviceHeaders, _Request, _TwoFactor, _path, _utf8)

STORE_PROTOCOLS = ("android_music", "macos_accounts", "configurator")


def _data(value):
    if isinstance(value, dict):
        value = json.dumps(value).encode("utf-8")
    elif isinstance(value, str):
        value = value.encode("utf-8")
    return (c.c_uint8 * len(value)).from_buffer_copy(value), len(value)


def _headers(value):
    if value is not None and (not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    )):
        raise TypeError("headers must map strings to strings")
    return json.dumps(value or {}).encode("utf-8")


def _app_id(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**64:
        raise ValueError("app_id must be a positive unsigned 64-bit integer")
    return value


class _StoreOwner(_NativeClient):
    def _start(self, library=None, transport=None, clock=None):
        library = library if isinstance(library, Library) else Library(library)
        self._init_callbacks(library, transport, clock)
        self._options = _Options(*self._callbacks, None)

    def _create(self, name, *arguments):
        try:
            self._check(self._library._function(name)(*arguments, c.byref(self._handle)))
        except BaseException:
            self.close()
            raise

    def _bytes(self, name, *arguments):
        self._prepare()
        return self._library._buffer(self._library._function(name), self._handle,
                                     *arguments, check=self._check)

    def _session(self, function, *arguments):
        result = c.c_void_p()
        try:
            self._check(function(*arguments, c.byref(result)))
            return StoreSession(self._library, result)
        except BaseException:
            if result:
                self._library._native.aauth_store_session_free(result)
            raise


class StoreClient(_StoreOwner):
    """Standalone Store identity; protocol defaults to Android Music for compatibility."""
    _free_name = "aauth_store_client_free"

    def __init__(self, directory, protocol="android_music", *, library=None,
                 transport=None, clock=None, user_agent=None, client_info=None, headers=None):
        if protocol not in STORE_PROTOCOLS:
            raise ValueError(f"protocol must be one of {STORE_PROTOCOLS}")
        self.protocol = protocol
        self._start(library, transport, clock)
        overrides = _DeviceHeaders(_utf8(user_agent, "User-Agent") if user_agent is not None else None,
                                   _utf8(client_info, "Client-Info") if client_info is not None else None)
        self._create("aauth_store_client_create", _path(directory), STORE_PROTOCOLS.index(protocol),
                     c.byref(self._options), c.byref(overrides), _headers(headers))

    def provision(self):
        self._prepare()
        self._check(self._library._function("aauth_store_client_provision")(self._handle))

    def headers(self):
        return json.loads(self._bytes("aauth_store_client_headers"))

    def login(self, *, email, password=None, two_factor=None):
        self._prepare()
        if self.protocol == "macos_accounts":
            raise ValueError("Mac Accounts requires login_with_pet()")
        if password is None:
            password = getpass.getpass("Apple ID password: ")
        if two_factor is None:
            two_factor = lambda: input("Apple ID verification code: ").strip()

        def verify(_context, output, capacity, written):
            try:
                code = two_factor().encode("ascii")
                if len(code) > capacity:
                    raise ValueError("Verification code exceeds the callback buffer")
                c.memmove(output, code, len(code))
                written[0] = len(code)
                return 0
            except BaseException as error:
                self._callback_error = error
                return -1

        callback = _TwoFactor(verify)
        return self._session(self._library._function("aauth_store_client_login"), self._handle,
                             _utf8(email, "Apple ID"), _utf8(password, "Password"), callback, None)

    def login_with_pet(self, *, email, account, device):
        """Mac Accounts only. device is a native Client or a high-level Device."""
        self._prepare()
        device = device if isinstance(device, Client) else device._client
        device._prepare()
        if device._library is not self._library:
            raise ValueError("Store client and device must use the same Library")
        plist = account.plist() if callable(account.plist) else account.plist
        with AccountSession.from_plist(plist, library=self._library) as native:
            function = self._library._function("aauth_store_client_login_with_pet")
            result = c.c_void_p()
            try:
                status = function(self._handle, _utf8(email, "Apple ID"), native._handle,
                                  device._handle, c.byref(result))
                if device._callback_error is not None:
                    device._check(status)
                self._check(status)
                return StoreSession(self._library, result)
            except BaseException:
                if result:
                    self._library._native.aauth_store_session_free(result)
                raise

    def request(self, session, url, *, method="GET", body=b"", headers=None):
        self._prepare()
        session._require_open()
        if session._library is not self._library:
            raise ValueError("Store session and client must use the same Library")
        raw_body, size = _data(body)
        request = _Request(_utf8(url, "URL"), _utf8(method, "Method"), _headers(headers), raw_body, size)
        value = json.loads(self._bytes("aauth_store_client_request", session._handle, c.byref(request)))
        return HttpResponse(value["status"], base64.b64decode(value["body"], validate=True),
                            tuple(tuple(pair) for pair in value["headers"]))


class TestFlightClient(_StoreOwner):
    _free_name = "aauth_testflight_client_free"

    def __init__(self, saved_session, *, library=None, transport=None, headers=None,
                 device_model=None, device_name=None, _from_cookies=False):
        self._start(library, transport)
        data, size = _data(saved_session)
        options = {"headers": json.loads(_headers(headers))}
        if device_model is not None:
            options["deviceModel"] = device_model
        if device_name is not None:
            options["deviceName"] = device_name
        function = "aauth_testflight_client_from_store_cookies" if _from_cookies else "aauth_testflight_client_create"
        self._create(function, data, size, c.byref(self._options), json.dumps(options).encode("utf-8"))

    @classmethod
    def load(cls, filename, *, encryption_key=None, **options):
        from .crypto import _read
        return cls.deserialize(_read(filename), encryption_key=encryption_key, **options)

    @classmethod
    def deserialize(cls, data, *, encryption_key=None, **options):
        from .crypto import _decode, _library
        library = _library(options.pop("library", None))
        return cls(_decode(data, encryption_key, library), library=library, **options)

    def serialize(self, *, encryption_key=None):
        from .crypto import _encode
        return _encode(self._bytes("aauth_testflight_client_serialize"), encryption_key, self._library)

    @classmethod
    def from_store_cookies(cls, context, **options):
        return cls(context, _from_cookies=True, **options)

    @classmethod
    def from_store_session(cls, session, hardware20, mac_headers, **options):
        options.setdefault("library", session._library)
        return cls.from_store_cookies(session.testflight_context(hardware20, mac_headers), **options)

    def save(self, filename, *, encryption_key=None):
        self._prepare()
        if encryption_key is not None:
            from .crypto import _save
            _save(filename, self.serialize(), encryption_key, self._library, overwrite=False)
            return
        self._check(self._library._function("aauth_testflight_client_save")(self._handle, _path(filename)))

    def catalog(self):
        return self._bytes("aauth_testflight_client_catalog")

    def install_metadata(self, bundle):
        return self._bytes("aauth_testflight_client_install_metadata", _utf8(bundle, "Bundle ID"))

    def download(self, bundle, destination):
        return json.loads(self._bytes("aauth_testflight_client_download", _utf8(bundle, "Bundle ID"), _path(destination)))


class AppStoreIosClient(_StoreOwner):
    _free_name = "aauth_appstore_ios_client_free"

    def __init__(self, context, country=None, *, library=None, transport=None, headers=None):
        if isinstance(context, StoreSession):
            if country is None:
                raise ValueError("country is required with a StoreSession")
            library = library or context._library
            context = context.ios_context(country)
        self._start(library, transport)
        data, size = _data(context)
        self._create("aauth_appstore_ios_client_create", data, size, c.byref(self._options), _headers(headers))

    @classmethod
    def load(cls, filename, **options):
        return cls(Path(filename).read_bytes(), **options)

    def catalog(self, app_id):
        return self._bytes("aauth_appstore_ios_client_catalog", _app_id(app_id))

    def offer(self, app_id):
        return json.loads(self._bytes("aauth_appstore_ios_client_offer", _app_id(app_id)))

    def metadata(self, app_id):
        return self._bytes("aauth_appstore_ios_client_metadata", _app_id(app_id))

    def acquire_free(self, app_id):
        return self._bytes("aauth_appstore_ios_client_acquire_free", _app_id(app_id))

    def download(self, app_id, destination):
        return json.loads(self._bytes("aauth_appstore_ios_client_download", _app_id(app_id), _path(destination)))


class AppStoreMacClient(_StoreOwner):
    _free_name = "aauth_appstore_mac_client_free"

    def __init__(self, session, store_directory, country, *, library=None, transport=None,
                 clock=None, user_agent=None, client_info=None, headers=None):
        session._require_open()
        self._start(library or session._library, transport, clock)
        if session._library is not self._library:
            raise ValueError("Store session and client must use the same Library")
        overrides = _DeviceHeaders(_utf8(user_agent, "User-Agent") if user_agent is not None else None,
                                   _utf8(client_info, "Client-Info") if client_info is not None else None)
        self._create("aauth_appstore_mac_client_create", session._handle, _path(store_directory),
                     _utf8(country, "Country"), c.byref(self._options), c.byref(overrides), _headers(headers))

    def catalog(self, app_id):
        return self._bytes("aauth_appstore_mac_client_catalog", _app_id(app_id))

    def offer(self, app_id):
        return json.loads(self._bytes("aauth_appstore_mac_client_offer", _app_id(app_id)))

    def metadata(self, app_id):
        return self._bytes("aauth_appstore_mac_client_metadata", _app_id(app_id))

    def download(self, app_id, destination):
        return json.loads(self._bytes("aauth_appstore_mac_client_download", _app_id(app_id), _path(destination), 0))

    def download_package(self, app_id, destination):
        return json.loads(self._bytes("aauth_appstore_mac_client_download", _app_id(app_id), _path(destination), 1))


def generate_kbsync(dsid, hardware, entropy=b"", *, library=None):
    library = library if isinstance(library, Library) else Library(library)
    raw, size = _data(hardware)
    seed, seed_size = _data(entropy)
    return library._buffer(library._function("aauth_generate_kbsync"), _app_id(dsid), raw, size, seed, seed_size)


def unwrap_testflight_transport(source, destination, hardware20, dp_info88, *, library=None):
    return _unwrap("aauth_unwrap_testflight_transport", source, destination, hardware20, dp_info88, library)


def unwrap_appstore_mac_package(source, destination, hardware6, dp_info88, *, library=None):
    return _unwrap("aauth_unwrap_appstore_mac_package", source, destination, hardware6, dp_info88, library)


def _unwrap(name, source, destination, hardware, dp_info, library):
    library = library if isinstance(library, Library) else Library(library)
    raw, size = _data(hardware)
    info, info_size = _data(dp_info)
    return json.loads(library._buffer(library._function(name), _path(source), _path(destination),
                                      raw, size, info, info_size))


def normalize_testflight_ipa(source, destination, expected_bundle="", *, library=None):
    library = library if isinstance(library, Library) else Library(library)
    return json.loads(library._buffer(library._function("aauth_normalize_testflight_ipa"),
        _path(source), _path(destination), _utf8(expected_bundle, "Bundle ID")))
