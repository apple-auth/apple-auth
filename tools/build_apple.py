#!/usr/bin/env python3
"""Build an Apple XCFramework with optional account client and Swift package."""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile


MBEDTLS_VERSION = "3.6.5"
MBEDTLS_SHA256 = "4a11f1777bb95bf4ad96721cac945a26e04bf19f57d905f241fe77ebeddf46d8"
ROOT = Path(__file__).resolve().parents[1]
JSON_VERSION = "3.12.0"
JSON_SHA256 = "42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa"


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def download(url, path, checksum):
    if not path.is_file():
        temporary = path.with_suffix(path.suffix + ".part")
        with urllib.request.urlopen(url, timeout=90) as response, temporary.open("wb") as dest:
            shutil.copyfileobj(response, dest)
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != checksum:
            raise RuntimeError(f"Dependency checksum mismatch: {temporary}")
        temporary.replace(path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
        raise RuntimeError(f"Dependency checksum mismatch: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/apple")
    parser.add_argument("--deployment-target", help="Minimum iOS version (client: 13.0, core: 15.0)")
    parser.add_argument("--device-only", action="store_true", help="Build only the arm64 device slice")
    parser.add_argument("--skip-swift-check", action="store_true", help="Check C/C++ independently of Swift")
    parser.add_argument("--with-client", action="store_true", help="Include the account client and Swift package")
    parser.add_argument("--include-macos", action="store_true", help="Include a universal macOS 12+ slice")
    args = parser.parse_args()
    args.deployment_target = args.deployment_target or ("13.0" if args.with_client else "15.0")
    if sys.platform != "darwin":
        parser.error("Apple builds require macOS and Xcode")
    for tool in ("cmake", "ninja", "xcrun", "xcodebuild", "swiftc"):
        if not shutil.which(tool):
            parser.error(f"Missing build tool: {tool}")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"mbedtls-{MBEDTLS_VERSION}.tar.bz2"
    url = (f"https://github.com/Mbed-TLS/mbedtls/releases/download/"
           f"mbedtls-{MBEDTLS_VERSION}/{archive.name}")
    download(url, archive, MBEDTLS_SHA256)
    source = output / f"mbedtls-{MBEDTLS_VERSION}"
    if not source.is_dir():
        subprocess.run(["cmake", "-E", "tar", "xjf", str(archive)], cwd=output, check=True)

    json_prefix = output / "json-install"
    if args.with_client:
        json_archive = output / "json.tar.xz"
        download(f"https://github.com/nlohmann/json/releases/download/v{JSON_VERSION}/json.tar.xz",
                 json_archive, JSON_SHA256)
        json_source = output / "json"
        if not json_source.is_dir():
            subprocess.run(["cmake", "-E", "tar", "xJf", str(json_archive)], cwd=output, check=True)
        run("cmake", "-S", json_source, "-B", output / "json-build", "-G", "Ninja",
            "-DJSON_BuildTests=OFF", f"-DCMAKE_INSTALL_PREFIX={json_prefix}")
        run("cmake", "--install", output / "json-build")

    libraries = {}
    platforms = [("iphoneos", "arm64")]
    if not args.device_only:
        platforms.append(("iphonesimulator", "arm64;x86_64"))
    if args.include_macos:
        platforms.append(("macosx", "arm64;x86_64"))
    availability = "-Werror=unguarded-availability -Werror=unguarded-availability-new"
    for sdk, architectures in platforms:
        folder = output / sdk
        prefix = folder / "dependencies"
        deployment = "12.0" if sdk == "macosx" else args.deployment_target
        common = ["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                  f"-DCMAKE_OSX_SYSROOT={sdk}", f"-DCMAKE_OSX_ARCHITECTURES={architectures}",
                  f"-DCMAKE_OSX_DEPLOYMENT_TARGET={deployment}",
                  f"-DCMAKE_C_FLAGS={availability}", f"-DCMAKE_CXX_FLAGS={availability}",
                  "-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO"]
        if sdk != "macosx":
            common.append("-DCMAKE_SYSTEM_NAME=iOS")
        run("cmake", "-S", source, "-B", folder / "mbedtls", *common,
            "-DENABLE_TESTING=OFF", "-DENABLE_PROGRAMS=OFF", "-DUSE_SHARED_MBEDTLS_LIBRARY=OFF",
            "-DUSE_STATIC_MBEDTLS_LIBRARY=ON", f"-DCMAKE_INSTALL_PREFIX={prefix}")
        run("cmake", "--build", folder / "mbedtls", "--parallel", "3")
        run("cmake", "--install", folder / "mbedtls")
        prefixes = f"{prefix};{json_prefix}" if args.with_client else str(prefix)
        run("cmake", "-S", ROOT, "-B", folder / "core", *common,
            f"-DCMAKE_PREFIX_PATH={prefixes}", f"-DCMAKE_FIND_ROOT_PATH={prefixes}",
            f"-DAPPLE_AUTH_WITH_CLIENT={'ON' if args.with_client else 'OFF'}", "-DAPPLE_AUTH_WITH_CURL=OFF",
            "-DAPPLE_AUTH_BUILD_EXAMPLES=OFF", "-DBUILD_SHARED_LIBS=OFF")
        run("cmake", "--build", folder / "core", "--parallel", "3")
        stage = folder / "install"
        run("cmake", "--install", folder / "core", "--prefix", stage)
        combined = folder / "libapple_auth.a"
        run("xcrun", "libtool", "-static", "-o", combined, *sorted((stage / "lib").glob("libapple_auth*.a")),
            *sorted((prefix / "lib").rglob("*.a")))
        headers = stage / "include"
        exported = "client_c_api.h" if args.with_client else "c_api.h"
        (headers / "module.modulemap").write_text(
            f'module apple_auth {{\n    header "apple_auth/{exported}"\n    export *\n}}\n', encoding="utf-8")
        probe = folder / "probe.cpp"
        probe.write_text('#include <apple_auth/c_api.h>\n'
                         'int main() { return aauth_version() == nullptr; }\n', encoding="utf-8")
        swift = folder / "probe.swift"
        swift.write_text('import apple_auth\nlet version = aauth_version()\n', encoding="utf-8")
        sdk_path = subprocess.check_output(
            ["xcrun", "--sdk", sdk, "--show-sdk-path"], text=True).strip()
        for architecture in architectures.split(";"):
            architecture_deployment = deployment
            if sdk == "iphonesimulator" and architecture == "arm64" and tuple(map(int, deployment.split("."))) < (14, 0):
                architecture_deployment = "14.0"
            target = f"{architecture}-apple-{'macos' if sdk == 'macosx' else 'ios'}{architecture_deployment}"
            if sdk == "iphonesimulator":
                target += "-simulator"
            run("xcrun", "--sdk", sdk, "clang++", "-target", target, "-isysroot", sdk_path,
                "-std=c++20", *availability.split(), "-I", headers, probe,
                f"-Wl,-force_load,{combined}", "-Wl,-fatal_warnings",
                *(["-framework", "CoreFoundation"] if args.with_client else []),
                "-o", folder / f"probe-{architecture}")
            if not args.skip_swift_check:
                run("xcrun", "swiftc", "-typecheck", "-target", target, "-sdk", sdk_path,
                    "-I", headers, swift)
                if args.with_client:
                    run("xcrun", "swiftc", "-typecheck", "-swift-version", "5", "-module-name", "AppleAuth",
                        "-target", target, "-sdk", sdk_path, "-I", headers,
                        *sorted((ROOT / "swift/AppleAuth/Sources/AppleAuth").glob("*.swift")))
        libraries[sdk] = (combined, headers)

    package = output / "package"
    package.mkdir(exist_ok=True)
    framework = package / "apple_auth.xcframework"
    if framework.exists():
        if framework.is_symlink() or framework.resolve().parent != output / "package":
            raise RuntimeError(f"Unsafe XCFramework output: {framework}")
        shutil.rmtree(framework)
    create = ["xcodebuild", "-create-xcframework"]
    for library, headers in libraries.values():
        create += ["-library", library, "-headers", headers]
    run(*create, "-output", framework)
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(ROOT / name, package)
    shutil.copytree(ROOT / "LICENSES", package / "licenses", dirs_exist_ok=True)
    shutil.copy2(source / "LICENSE", package / "licenses/MbedTLS-XCFramework.txt")
    if args.with_client:
        shutil.copy2(json_source / "LICENSE.MIT", package / "licenses/nlohmann-json-XCFramework.txt")
        swift_package = package / "AppleAuth"
        shutil.copytree(ROOT / "swift/AppleAuth", swift_package, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(".build", ".swiftpm", "Artifacts"))
        shutil.copytree(framework, swift_package / "Artifacts/apple_auth.xcframework", dirs_exist_ok=True)
        shutil.copytree(package / "licenses", swift_package / "Licenses", dirs_exist_ok=True)
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copy2(ROOT / name, swift_package)
        for name, folder in (("apple_auth.xcframework", framework), ("AppleAuth", swift_package)):
            with zipfile.ZipFile(package / f"{name}.zip", "w", zipfile.ZIP_DEFLATED) as bundle:
                for item in sorted(folder.rglob("*")):
                    if item.is_file():
                        bundle.write(item, item.relative_to(folder.parent))
                if name == "apple_auth.xcframework":
                    for notice in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
                        bundle.write(package / notice, notice)
                    for item in sorted((package / "licenses").rglob("*")):
                        if item.is_file():
                            bundle.write(item, item.relative_to(package))
    print(f"\nBuilt {framework}")


if __name__ == "__main__":
    main()
