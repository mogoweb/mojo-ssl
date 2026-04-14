# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is BoringSSL, Google's fork of OpenSSL designed for Chrome/Chromium and other Google projects. It is a cryptographic library providing SSL/TLS implementation and various cryptographic primitives.

**Note**: BoringSSL does not guarantee API or ABI stability. Changes are made as needed for Google's use cases.

## Build Commands

### Building (CMake + Ninja - recommended)
```bash
# Debug build (default)
cmake -GNinja -B build
ninja -C build

# Release build
cmake -GNinja -B build -DCMAKE_BUILD_TYPE=Release
ninja -C build

# Clean rebuild
rm -rf build && cmake -GNinja -B build && ninja -C build
```

### Build Options
- `-DBUILD_SHARED_LIBS=1` - Build as shared library
- `-DOPENSSL_SMALL=1` - Optimize for binary size over performance
- `-DBORINGSSL_PREFIX=<prefix>` - Add custom prefix to all symbols
- `-DCMAKE_TOOLCHAIN_FILE=...` - Cross-compilation

## Adding New Files

See `.claude/rules/build.md` for instructions on adding new source files.

## Testing

See `.claude/rules/testing.md` for testing commands.

## Code Architecture

### Directory Structure
- `crypto/` - Core cryptographic library (libcrypto)
  - `fipsmodule/` - FIPS 140-2 validated algorithms (AES, SHA, RSA, EC, etc.)
  - Subdirectories per algorithm: `aes/`, `bn/`, `ec/`, `rsa/`, `curve25519/`, etc.
  - `internal.h` - Internal utilities and low-level APIs
  - `x509/` - X.509 certificate handling
- `ssl/` - SSL/TLS library (libssl)
  - `internal.h` - SSL internal structures
  - `handshake_client.cc`, `handshake_server.cc` - Handshake logic
  - `tls13_*.cc` - TLS 1.3 implementation
- `include/openssl/` - Public API headers with documentation
- `pki/` - Certificate validation and path building (C++)
- `decrepit/` - Legacy algorithms (DES, MD4, MD5, RC4) - avoid using
- `rust/` - Rust bindings (`bssl-sys`, `bssl-crypto`, `bssl-tls`)
- `gen/` - Pre-generated assembly and error data
- `util/` - Build tools, test runners, documentation generators
- `fuzz/` - Fuzzing targets

### Key Libraries
- `libcrypto` - Core cryptographic primitives
- `libssl` - SSL/TLS protocol implementation
- `libpki` - Certificate validation

### libssl Notes
- Originally C, being incrementally rewritten in C++11
- On Linux, may not depend on C++ runtime - use utilities from `ssl/internal.h`
- Check with `util/check_imported_libraries.go` for shared library builds

## Coding Style

See `.claude/rules/coding-style.md` for coding conventions.

## API Conventions

See `.claude/rules/api-conventions.md` for API conventions and common patterns.

## Dependencies

- CMake 3.22+
- C11 and C++17 compilers
- Go (latest stable) - for running tests
- Ninja (recommended) or Make
- NASM (Windows only)
- Perl - for pre-generated files
- libunwind 1.3.0+ (optional, x86_64 Linux, for thorough assembly tests)
