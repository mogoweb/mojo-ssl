# BoringSSL Coding Style

Follows [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with C-specific conventions:

## C Files

- `typedef struct foo_st FOO;` for struct naming
- `MODULE_function_name` for public functions
- `TYPE_NAME_new`/`TYPE_NAME_free` for heap-allocated types
- `TYPE_NAME_init`/`TYPE_NAME_cleanup` for stack-allocated types
- Use `// C99-style` comments
- Pointer style: `uint8_t *ptr` (not `uint8_t* ptr`)

## Return Values

- `int` functions: return `1` on success, `0` on error
- Pointer functions: return non-NULL on success, `NULL` on error
- Never overload return value for both status and output

## Memory

- Use `OPENSSL_malloc()`/`OPENSSL_free()` instead of `malloc()`/`free()`
- Use wrappers from `crypto/internal.h`: `OPENSSL_memchr`, `OPENSSL_memcpy`, etc.

## Integers

- Use explicitly-sized types: `uint8_t`, `uint16_t`, `size_t`
- Avoid `ssize_t` (MSVC lacks it)

## Documentation

- All public symbols must have documentation in header files
- Format: `// FUNCTION_NAME does X with |param|. Returns 1 on success.`
