# BoringSSL Testing

## Run All Tests

```bash
# Using Ninja (recommended)
ninja -C build run_tests

# Or using Go directly
go run util/all_tests.go    # C/C++ tests
cd ssl/test/runner && go test   # Blackbox TLS tests
```

## Run Individual Test Binaries

```bash
./build/crypto_test
./build/ssl_test
./build/pki_test
./build/decrepit_test
```

## Run Specific Test Filters

```bash
./build/crypto_test --gtest_filter=AESTest*
./build/ssl_test --gtest_filter=SSLTest.Connect
```

## Benchmarks

```bash
./build/bssl_bench --benchmark_list_tests
./build/bssl_bench --benchmark_filter=SHA256
```
