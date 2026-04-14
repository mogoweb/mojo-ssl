# BoringSSL Build File Management

When adding new source files to BoringSSL:

## Step 1: Edit build.json

`build.json` at the repository root is the authoritative source for all source files.

Add new file paths to the `srcs` field of the appropriate target (e.g., crypto, ssl, crypto_test, etc.) based on file type.

## Step 2: Run the pregenerate tool

```bash
go run ./util/pregenerate
```

This updates all pre-generated files in the `gen/` directory (sources.cmake, sources.json, sources.bzl, sources.gni, sources.mk).

## Step 3: Rebuild

```bash
cmake -GNinja -B build
ninja -C build
```

CMake will automatically detect changes to `gen/sources.cmake` and reconfigure.

## Verify Generated Files Are Up-to-Date

CI automatically checks that pre-generated files match `build.json`. To verify locally:

```bash
go run ./util/pregenerate -check
```

## Important Notes

- **Only modify `build.json`** - Do NOT directly edit `gen/sources.*` files
- The `gen/` files are generated from `build.json` and will be overwritten by pregenerate
