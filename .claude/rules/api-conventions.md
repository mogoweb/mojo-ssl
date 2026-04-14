# BoringSSL API Conventions

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
