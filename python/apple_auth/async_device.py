"""Async device facade. Native calls stay in a bounded thread executor."""
from __future__ import annotations

import asyncio
from concurrent.futures import CancelledError as WorkerCancelledError, ThreadPoolExecutor
import contextvars
import inspect
import os
from pathlib import Path
import threading
from typing import Awaitable, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from apple_auth import Device, DeviceInfo, Session, StoreSession, HttpResponse

_VERIFICATION_DEVICE = contextvars.ContextVar("apple_auth_verification_device", default=None)


class _Operation:
    """Cancellation shared between the awaiting task and a native 2FA callback."""

    def __init__(self, device=None):
        self.device = device
        self.started = False  # Accessed only on the owning event loop.
        self._cancelled = threading.Event()
        self._verification = None
        self._guard = threading.Lock()

    def cancel(self):
        self._cancelled.set()
        with self._guard:
            if self._verification is not None:
                self._verification.cancel()

    def _check_cancelled(self):
        if self._cancelled.is_set():
            raise WorkerCancelledError("Login caller was cancelled")

    def verification_code(self, callback, loop) -> str:
        self._check_cancelled()
        value = callback() if callback else input("Trusted-device verification code: ").strip()
        if inspect.isawaitable(value):
            async def receive():
                token = _VERIFICATION_DEVICE.set(self.device)
                try:
                    return await value
                finally:
                    _VERIFICATION_DEVICE.reset(token)

            coroutine = receive()
            try:
                future = asyncio.run_coroutine_threadsafe(coroutine, loop)
            except BaseException:
                coroutine.close()
                if inspect.iscoroutine(value):
                    value.close()
                raise
            with self._guard:
                self._verification = future
                if self._cancelled.is_set():
                    future.cancel()
            try:
                result = future.result()
            finally:
                with self._guard:
                    self._verification = None
            value = result
        self._check_cancelled()
        if not isinstance(value, str):
            raise TypeError("two_factor must return a string")
        return value


async def _finish_native(future, operation=None):
    """Even direct task cancellation must not release a still-running native client."""
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        if operation is not None:
            operation.cancel()
        while not future.done():
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        if not future.cancelled():
            future.exception()
        raise


class AsyncDevice:
    """Async counterpart to Device, bound to one event loop and one state directory.

    Construction is lazy. Use ``async with`` or ``await ready()`` to initialize.
    Different devices share the event loop's bounded thread pool by default;
    an explicit ThreadPoolExecutor can be supplied without transferring ownership.
    """

    def __init__(self, state: str | os.PathLike | None = None, *,
                 platform: str | None = None, model: str | None = None,
                 os_version: str | None = None, os_build: str | None = None,
                 serial_number: str | None = None, library=None, transport=None, clock=None,
                 user_agent: str | None = None, client_info: str | None = None,
                 headers: dict[str, str] | None = None,
                 encryption_key: bytes | None = None,
                 in_memory: bool = False, initial_state: bytes | None = None,
                 executor: ThreadPoolExecutor | None = None):
        from .device import _new_device_directory
        from .crypto import _key

        if executor is not None and not isinstance(executor, ThreadPoolExecutor):
            raise TypeError("executor must be a ThreadPoolExecutor")
        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must map strings to strings")
        if in_memory and state is not None:
            raise ValueError("An in-memory device cannot have a state directory")
        if initial_state is not None and not in_memory:
            raise ValueError("Restore snapshots into an in-memory device")
        self._state = None if in_memory else (Path(state) if state is not None else _new_device_directory()).expanduser().resolve()
        self._settings = dict(platform=platform, model=model, os_version=os_version,
                              os_build=os_build, serial_number=serial_number,
                              user_agent=user_agent, client_info=client_info,
                              headers=headers.copy() if headers is not None else None,
                              library=library, transport=transport, clock=clock,
                              in_memory=in_memory, initial_state=bytes(initial_state) if initial_state is not None else None,
                              encryption_key=_key(encryption_key) if encryption_key is not None else None)
        self._executor = executor
        self._reopen = False
        self._device: Device | None = None
        self._loop = None
        self._lock = None
        self._jobs = set()
        self._closing = False
        self._closed = False
        self._close_task = None

    @classmethod
    def memory(cls, *, initial_state: bytes | None = None, platform: str | None = None, **options) -> AsyncDevice:
        """Keep identity/ADI in RAM; optionally restore a serialized snapshot."""
        return cls(in_memory=True, initial_state=initial_state,
                   platform=platform if platform is not None else ("mac" if initial_state is None else None),
                   **options)

    @classmethod
    def mac(cls, state: str | os.PathLike | None = None, *, model: str | None = None,
            macos: str | None = None, build: str | None = None,
            serial_number: str | None = None, **options) -> AsyncDevice:
        return cls(state, platform="mac", model=model, os_version=macos, os_build=build,
                   serial_number=serial_number, **options)

    @classmethod
    def iphone(cls, state: str | os.PathLike | None = None, *, model: str | None = None,
               ios: str | None = None, build: str | None = None,
               serial_number: str | None = None, **options) -> AsyncDevice:
        return cls(state, platform="iphone", model=model, os_version=ios, os_build=build,
                   serial_number=serial_number, **options)

    @classmethod
    def windows(cls, state: str | os.PathLike | None = None, *,
                serial_number: str | None = None, **options) -> AsyncDevice:
        return cls(state, platform="windows", serial_number=serial_number, **options)

    @classmethod
    def android(cls, state: str | os.PathLike | None = None, **options) -> AsyncDevice:
        """Create/reopen an Android identity backed by native ADI (platform 4)."""
        return cls(state, platform="android", **options)

    @classmethod
    def open(cls, state: str | os.PathLike, **options) -> AsyncDevice:
        device = cls(state, **options)
        device._reopen = True
        return device

    @property
    def state(self) -> Path | None:
        return self._state

    @property
    def info(self) -> DeviceInfo:
        if self._device is None:
            raise RuntimeError("Device is not initialized; use async with or await ready()")
        return self._device.info

    def _bind_loop(self):
        if _VERIFICATION_DEVICE.get() is self:
            raise RuntimeError("A 2FA callback cannot call the same AsyncDevice")
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
            self._lock = asyncio.Lock()
        elif self._loop is not loop:
            raise RuntimeError("AsyncDevice belongs to another event loop")
        return loop

    def _ensure_device(self) -> Device:
        from .device import Device

        if self._device is None:
            factory = Device.open if self._reopen else Device
            self._device = factory(self.state, **self._settings)
        return self._device

    def _job_finished(self, task):
        self._jobs.discard(task)
        if not task.cancelled():
            task.exception()  # A cancelled waiter may no longer retrieve this result.

    async def _execute(self, function, operation):
        async with self._lock:
            operation.started = True
            context = contextvars.copy_context()
            future = self._loop.run_in_executor(
                self._executor, context.run, lambda: function(self._ensure_device()))
            return await _finish_native(future, operation)

    async def _call(self, function, operation=None):
        loop = self._bind_loop()
        if self._closing or self._closed:
            raise RuntimeError("AsyncDevice is closing or closed")
        operation = operation or _Operation()
        job = loop.create_task(self._execute(function, operation))
        self._jobs.add(job)
        job.add_done_callback(self._job_finished)
        try:
            return await asyncio.shield(job)
        except asyncio.CancelledError:
            operation.cancel()
            if not operation.started:
                job.cancel()
            raise

    async def ready(self) -> AsyncDevice:
        """Initialize local identity in a worker, without provisioning or account HTTP."""
        await self._call(lambda device: None)
        return self

    async def serialize_state(self) -> bytes:
        return await self._call(lambda device: device.serialize_state())

    async def provision(self) -> AsyncDevice:
        await self._call(lambda device: device.provision())
        return self

    async def headers(self) -> dict[str, str]:
        return await self._call(lambda device: device.headers())

    async def load_session(self) -> Session | None:
        """Read the saved session off the event loop; does not validate token expiry."""
        return await self._call(lambda device: device.session)

    async def login(self, *, email: str, password: str | None = None,
                    two_factor: Callable[[], str | Awaitable[str]] | None = None) -> Session:
        operation = _Operation(self)
        return await self._call(
            lambda device: device.login(email=email, password=password,
                two_factor=lambda: operation.verification_code(two_factor, self._loop)), operation)

    async def provision_store(self) -> AsyncDevice:
        await self._call(lambda device: device.provision_store())
        return self

    async def store_headers(self) -> dict[str, str]:
        return await self._call(lambda device: device.store_headers())

    async def load_store_session(self) -> StoreSession | None:
        return await self._call(lambda device: device.store_session)

    async def login_store(self, *, email: str, password: str | None = None,
                          two_factor: Callable[[], str | Awaitable[str]] | None = None) -> StoreSession:
        operation = _Operation(self)
        return await self._call(lambda device: device.login_store(email=email, password=password,
            two_factor=lambda: operation.verification_code(two_factor, self._loop)), operation)

    async def store_request(self, url: str, *, method: str = "GET", body: bytes = b"",
                            headers: dict[str, str] | None = None, session: StoreSession | None = None) -> HttpResponse:
        return await self._call(lambda device: device.store_request(url, method=method, body=body,
                                                                   headers=headers, session=session))

    async def login_store_with_pet(self, *, email: str, account: Session | None = None) -> StoreSession:
        return await self._call(lambda device: device.login_store_with_pet(email=email, account=account))

    async def developer_session(self, account: Session | None = None) -> dict:
        return await self._call(lambda device: device.developer_session(account))

    async def developer_headers(self, session: dict) -> dict[str, str]:
        return await self._call(lambda device: device.developer_headers(session))

    async def _close(self):
        try:
            if self._jobs:
                await _finish_native(asyncio.gather(*self._jobs, return_exceptions=True))
        finally:
            try:
                if self._device is not None:
                    await _finish_native(self._loop.run_in_executor(self._executor, self._device.close))
            finally:
                self._closed = True

    async def aclose(self):
        """Reject new operations, drain earlier calls and release the native client."""
        loop = self._bind_loop()
        if self._close_task is None:
            self._closing = True
            self._close_task = loop.create_task(self._close())
            self._close_task.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        await asyncio.shield(self._close_task)

    async def __aenter__(self) -> AsyncDevice:
        try:
            return await self.ready()
        except BaseException:
            await self.aclose()
            raise

    async def __aexit__(self, *_):
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncDevice(state={str(self.state)!r}, closed={self._closed})"
