#!/usr/bin/env python3
"""Fresh device provisioning and native GrandSlam login, with wall-clock timings."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import getpass
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import statistics
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "python"))
from apple_auth import DEVICE_PLATFORMS, Library, NativeError  # noqa: E402


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, help="New/empty state directory; default is a unique per-run directory")
    parser.add_argument("--reuse", action="store_true", help="Explicitly reuse --state instead of starting fresh")
    parser.add_argument("--device", choices=DEVICE_PLATFORMS,
                        help="ADI device platform; default: saved platform or windows. iPhone is experimental")
    parser.add_argument("--mac-model", help="Mac model identifier, e.g. MacBookAir10,1; saved or MacBookPro18,3 by default")
    parser.add_argument("--macos-version", help="macOS version, e.g. 14.4.1; supply --macos-build when changing it")
    parser.add_argument("--macos-build", help="macOS build, e.g. 23E224; inferred for known versions, required for others")
    parser.add_argument("--provision-only", action="store_true",
                        help="Provision and generate headers without asking for credentials or logging in")
    parser.add_argument("--library", type=Path, help="apple_auth_client.dll / libapple_auth_client.so")
    parser.add_argument("--dll-dir", type=Path, action="append", default=[], help="Extra dependency directory on Windows")
    parser.add_argument("--iterations", type=int, default=0, help="Optional local anisette benchmark calls; default: disabled")
    parser.add_argument("--report", type=Path, help="Timing JSON path; default: STATE/timings.json")
    args = parser.parse_args(argv)
    if args.reuse and args.state is None:
        parser.error("--reuse requires --state")
    if any((args.mac_model, args.macos_version, args.macos_build)) and args.device not in (None, "mac"):
        parser.error("--mac-model and --macos-* require --device mac or a saved Mac identity")
    if not 0 <= args.iterations <= 100_000:
        parser.error("--iterations must be between 0 and 100000")
    return args


def state_directory(args) -> Path:
    if args.state is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        root = PROJECT / ".local"
        if PROJECT.parent.name == "share":
            variable = "LOCALAPPDATA" if os.name == "nt" else "XDG_STATE_HOME"
            root = Path(os.environ.get(variable) or Path.home() / ".local" / "state") / "apple-auth"
        return root / "login" / f"{stamp}-{secrets.token_hex(4)}"
    path = args.state.expanduser().resolve()
    if path.exists() and not path.is_dir():
        raise ValueError("--state must name a directory")
    if path.is_dir() and any(path.iterdir()) and not args.reuse:
        raise ValueError("State directory is not empty; choose a new directory or explicitly pass --reuse")
    return path


def is_profile_name(name):
    return name == "adi.pb" or re.fullmatch(r"adi-[0-9a-fA-F]{8}\.pb", name) is not None


def has_profile(directory):
    return (directory / "adi.pb").exists() or any(
        file.is_file() and is_profile_name(file.name) for file in directory.glob("adi-*.pb"))


def report_path(args, directory):
    path = args.report.expanduser().resolve() if args.report is not None else directory / "timings.json"
    protected = {directory / name for name in ("identity.json", "adi.pb", "account-session.plist")}
    if is_profile_name(path.name) or path.resolve() in {value.resolve() for value in protected}:
        raise ValueError("The timing report cannot overwrite credentials, identity, profile or session files")
    return path


class Measurements:
    def __init__(self, report):
        self.report = report
        self.input_ns = 0
        self.two_factor_ns = 0
        self.started = time.perf_counter_ns()

    def user_input(self, operation, *, two_factor=False):
        start = time.perf_counter_ns()
        try:
            return operation()
        finally:
            elapsed = time.perf_counter_ns() - start
            self.input_ns += elapsed
            if two_factor:
                self.two_factor_ns += elapsed

    def measure(self, name, label, operation, client=None):
        print(f"{label}...", flush=True)
        first = len(client.http_timings) if client is not None else 0
        start = time.perf_counter_ns()
        input_before = self.input_ns
        try:
            return operation()
        finally:
            wall = (time.perf_counter_ns() - start) / 1e9
            waiting = (self.input_ns - input_before) / 1e9
            events = client.http_timings[first:] if client is not None else []
            http = sum(event.seconds for event in events)
            self.report["stages"][name] = {"wall_seconds": wall, "input_wait_seconds": waiting,
                "active_seconds": max(0.0, wall - waiting), "http_seconds": http,
                "local_wall_seconds": max(0.0, wall - waiting - http), "http_requests": len(events)}
            self.report["http"].extend({"stage": name, **asdict(event)} for event in events)
            print(f"  {wall * 1000:.3f} ms" + (f"; HTTP: {http * 1000:.3f} ms" if events else ""), flush=True)


def read_credentials(_args, measurements):
    email = measurements.user_input(lambda: input("Apple ID email: ").strip())
    password = measurements.user_input(lambda: getpass.getpass("Apple ID password: "))
    if not email or not password:
        raise ValueError("Apple ID and password are required")
    return email, password


def verification_code():
    while True:
        code = "".join(input("Trusted-device verification code (6 digits): ").split())
        if len(code) == 6 and all(character in "0123456789" for character in code):
            return code
        print("Enter exactly six digits.", flush=True)


def benchmark_headers(client, count):
    before = len(client.http_timings)
    samples = []
    start = time.perf_counter_ns()
    for _ in range(count):
        tick = time.perf_counter_ns()
        client.headers()
        if len(client.http_timings) != before:
            raise RuntimeError("Warm header benchmark unexpectedly performed HTTP requests")
        samples.append((time.perf_counter_ns() - tick) / 1e9)
    elapsed = (time.perf_counter_ns() - start) / 1e9
    ordered = sorted(samples)
    return {"iterations": count, "elapsed_seconds": elapsed,
            "mean_seconds": statistics.fmean(samples), "median_seconds": statistics.median(samples),
            "p95_seconds": ordered[math.ceil(0.95 * count) - 1],
            "min_seconds": ordered[0], "max_seconds": ordered[-1],
            "operations_per_second": count / elapsed if elapsed else 0.0,
            "http_requests": 0, "includes_python_ffi_and_json": True}


def run(args, *, transport=None, clock=None, credentials_provider=read_credentials,
        code_provider=verification_code, library_factory=Library):
    """Run one login with optional transport, clock and credential callbacks."""
    directory = state_directory(args)
    report_path(args, directory)
    report = {"schema_version": 1, "status": "running", "authenticated": False,
              "started_utc": datetime.now(timezone.utc).isoformat(), "state_directory": str(directory),
              "fresh_profile": not has_profile(directory),
              "operation": "provision" if args.provision_only else "login",
              "provisioning_platform": "mac" if args.device == "mac" else "windows",
              "transport": "custom" if transport else "curl",
              "python": platform.python_version(), "platform": platform.system(),
              "stages": {}, "http": []}
    measurements = Measurements(report)
    client = session = None
    try:
        library = measurements.measure("library_load", "Loading apple-auth",
            lambda: library_factory(args.library, dll_directories=args.dll_dir))
        report["library"] = str(library.path)
        report["library_version"] = library.version
        client = measurements.measure("identity_init", "Initializing local device identity",
            lambda: library.client(directory, device_platform=args.device, mac_model=args.mac_model,
                                   macos_version=args.macos_version, macos_build=args.macos_build,
                                   transport=transport, clock=clock))
        report["device_platform"] = client.device_platform
        device = client.mac_device
        if device is not None:
            report["mac_device"] = device
            print(f"Mac: {device['model']}, macOS {device['macos_version']} ({device['macos_build']})", flush=True)
        report["provisioning_platform"] = "mac" if client.device_platform == "mac" else "windows"
        print(f"Device platform: {client.device_platform}", flush=True)
        print(f"ADI provisioning platform: {report['provisioning_platform']}", flush=True)
        measurements.measure("provisioning", "Provisioning ADI profile", client.provision, client)
        measurements.measure("headers_first", "Generating first anisette headers", client.headers, client)

        def get_code():
            return measurements.user_input(code_provider, two_factor=True)

        if not args.provision_only:
            email, password = measurements.measure("credentials", "Enter your credentials",
                lambda: credentials_provider(args, measurements))
            session = measurements.measure("login", "GrandSlam login and 2FA",
                lambda: client.login(email, password, get_code), client)
            password = ""
            report["authenticated"] = True
            session_path = directory / "account-session.plist"
            measurements.measure("session_save", "Saving authenticated session", lambda: session.save(session_path))
            report["session_file"] = str(session_path)
        if args.iterations:
            report["headers_benchmark"] = measurements.measure("headers_benchmark", "Benchmarking warm anisette generation",
                lambda: benchmark_headers(client, args.iterations), client)
        report["status"] = "success"
    except KeyboardInterrupt:
        report["status"] = "canceled"
        report["error"] = {"type": "KeyboardInterrupt", "message": "Input canceled"}
    except Exception as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        if isinstance(error, NativeError):
            report["error"]["native_status"] = error.status
    finally:
        if session is not None:
            session.close()
        if client is not None:
            client.close()
        wall = (time.perf_counter_ns() - measurements.started) / 1e9
        bench = report["stages"].get("headers_benchmark", {}).get("wall_seconds", 0.0)
        report["total_wall_seconds"] = wall
        report["input_wait_seconds"] = measurements.input_ns / 1e9
        report["two_factor_wait_seconds"] = measurements.two_factor_ns / 1e9
        report["workflow_wall_seconds"] = max(0.0, wall - bench)
        report["workflow_active_seconds"] = max(0.0, wall - bench - measurements.input_ns / 1e9)
        report["http_seconds"] = sum(event["seconds"] for event in report["http"])
    return report


def write_report(report, args):
    directory = Path(report["state_directory"])
    if args.report is None and not directory.is_dir():
        return None
    path = report_path(args, directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
    return path


def print_summary(report):
    print(f"\n{'Stage':25s} {'Total, ms':>11s} {'HTTP, ms':>12s} {'Input, ms':>12s} {'Local, ms':>14s}")
    for name, stage in report["stages"].items():
        print(f"{name:25s} {stage['wall_seconds'] * 1000:11.3f} {stage['http_seconds'] * 1000:12.3f}"
              f" {stage['input_wait_seconds'] * 1000:12.3f} {stage['local_wall_seconds'] * 1000:14.3f}")
    print(f"\nWorkflow excluding benchmark:    {report['workflow_wall_seconds']:.3f} s")
    print(f"Workflow excluding manual input: {report['workflow_active_seconds']:.3f} s")
    print(f"2FA input wait:                  {report['two_factor_wait_seconds']:.3f} s")
    print(f"HTTP: {len(report['http'])} requests, {report['http_seconds']:.3f} s total")
    for index, event in enumerate(report["http"], 1):
        print(f"  {index:2d}. {event['stage']:13s} {event['method']:4s} {event['status']:3d}"
              f" {event['seconds'] * 1000:10.3f} ms  {event['host']}{event['path']}")
    bench = report.get("headers_benchmark")
    if bench:
        print(f"\nAnisette through Python/FFI/JSON, {bench['iterations']} calls without HTTP:")
        print(f"  median {bench['median_seconds'] * 1e6:.2f} µs; p95 {bench['p95_seconds'] * 1e6:.2f} µs;"
              f" mean {bench['mean_seconds'] * 1e6:.2f} µs; {bench['operations_per_second']:.0f} calls/s")
    print("Local = elapsed time outside HTTP and manual input; includes crypto, FFI and filesystem I/O.")
    if report["status"] == "success":
        if report["authenticated"]:
            print(f"Login succeeded. Session saved to: {report['session_file']}")
        else:
            print(f"Provisioning succeeded. Device state saved to: {report['state_directory']}")
    else:
        print(f"{report['status']}: {report['error']['message']}", file=sys.stderr)


def main(argv=None):
    args = arguments(argv)
    try:
        report = run(args)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    print_summary(report)
    try:
        path = write_report(report, args)
        if path:
            print(f"Timing report (JSON): {path}")
    except (OSError, ValueError) as error:
        print(f"Cannot save timing report: {error}", file=sys.stderr)
        return 1
    return 0 if report["status"] == "success" else (130 if report["status"] == "canceled" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
