# BoringSSL Build File Management

When adding new source files to BoringSSL:

1. **Only modify `build.json`** - Do NOT directly edit `gen/sources.*` files
2. **Run `go run ./util/pregenerate`** - This auto-generates all `gen/sources.cmake`, `gen/sources.json`, `gen/sources.bzl`, `gen/sources.gni`, `gen/sources.mk`

The `gen/` files are generated from `build.json` and will be overwritten by pregenerate.
