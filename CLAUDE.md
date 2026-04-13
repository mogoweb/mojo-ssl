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

## 如何添加新文件

### 第一步：编辑 build.json

build.json 位于仓库根目录，是所有源文件的权威来源。

根据文件类型，将新文件路径添加到对应目标（如 crypto、ssl、crypto_test 等）的 srcs 字段中。

### 第二步：运行预生成工具

```
go run ./util/pregenerate
```

这会更新 gen/ 目录下的所有预生成文件（sources.cmake、sources.json、sources.bzl 等）。

### 第三步：重新构建

```
cmake -GNinja -B build  
ninja -C build
```

CMake 会自动检测到 gen/sources.cmake 的变化并重新配置。 BUILDING.md:70-72

### 验证生成文件是否最新

CI 会自动检查预生成文件是否与 build.json 一致，本地也可以用以下命令验证：

```
go run ./util/pregenerate -check
```

## Testing

### Run all tests
```bash
# Using Ninja (recommended)
ninja -C build run_tests

# Or using Go directly
go run util/all_tests.go    # C/C++ tests
cd ssl/test/runner && go test   # Blackbox TLS tests
```

### Run individual test binaries
```bash
./build/crypto_test
./build/ssl_test
./build/pki_test
./build/decrepit_test
```

### Run specific test filters
```bash
./build/crypto_test --gtest_filter=AESTest*
./build/ssl_test --gtest_filter=SSLTest.Connect
```

## Benchmarks

```bash
./build/bssl_bench --benchmark_list_tests
./build/bssl_bench --benchmark_filter=SHA256
```

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

Follows [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with C-specific conventions:

### C Files
- `typedef struct foo_st FOO;` for struct naming
- `MODULE_function_name` for public functions
- `TYPE_NAME_new`/`TYPE_NAME_free` for heap-allocated types
- `TYPE_NAME_init`/`TYPE_NAME_cleanup` for stack-allocated types
- Use `// C99-style` comments
- Pointer style: `uint8_t *ptr` (not `uint8_t* ptr`)

### Return Values
- `int` functions: return `1` on success, `0` on error
- Pointer functions: return non-NULL on success, `NULL` on error
- Never overload return value for both status and output

### Memory
- Use `OPENSSL_malloc()`/`OPENSSL_free()` instead of `malloc()`/`free()`
- Use wrappers from `crypto/internal.h`: `OPENSSL_memchr`, `OPENSSL_memcpy`, etc.

### Integers
- Use explicitly-sized types: `uint8_t`, `uint16_t`, `size_t`
- Avoid `ssize_t` (MSVC lacks it)

### Documentation
- All public symbols must have documentation in header files
- Format: `// FUNCTION_NAME does X with |param|. Returns 1 on success.`

## API Conventions

See `API-CONVENTIONS.md` for full details. Key points:

- **Error handling**: Check return value first, then error queue if needed
- **Ownership**: Functions named `get0` return non-owning pointers; `get1`/`new` return owning pointers
- **Stack-allocated types**: Must call `_init()` to enter zero state, `_cleanup()` on all paths
- **Heap-allocated types**: Use `bssl::UniquePtr<T>` in C++
- **Callbacks**: Use `ex_data` to associate closure data with objects

## Common Patterns

### Stack-allocated context with cleanup
```c
EVP_MD_CTX ctx;
EVP_MD_CTX_init(&ctx);
int ok = EVP_DigestInit_ex(&ctx, EVP_sha256(), NULL) &&
         EVP_DigestUpdate(&ctx, data, len) &&
         EVP_DigestFinal_ex(&ctx, out, &out_len);
EVP_MD_CTX_cleanup(&ctx);
```

### Error handling with goto
```c
int ret = 0;
EVP_MD_CTX ctx;
EVP_MD_CTX_init(&ctx);

if (!some_operation()) {
  goto err;
}
// ... more operations ...
ret = 1;

err:
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
```

## Platform-Specific Notes

### ARM
- Capabilities determined via ACLE symbols (`__ARM_NEON`, `__ARM_FEATURE_AES`) or `-march`
- Define `OPENSSL_STATIC_ARMCAP` to disable runtime queries

### Windows
- Requires NASM for assembly
- MSVC from Visual Studio 2022+ required
- Visual Studio generator not fully supported (use Ninja)

### Android
```bash
cmake -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-21 \
      -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
      -GNinja -B build
```

## Dependencies

- CMake 3.22+
- C11 and C++17 compilers
- Go (latest stable) - for running tests
- Ninja (recommended) or Make
- NASM (Windows only)
- Perl - for pre-generated files
- libunwind 1.3.0+ (optional, x86_64 Linux, for thorough assembly tests)
