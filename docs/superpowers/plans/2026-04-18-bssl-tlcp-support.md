# bssl TLCP Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TLCP protocol support to bssl command-line tool with ECC_SM2_SM4_CBC_SM3 cipher suite support

**Architecture:** Extend existing bssl client/server tools to recognize -tlcp flag and TLCP-specific certificate parameters, configure SSL_CTX with TLCP methods and dual certificates

**Tech Stack:** BoringSSL C++ API, TLCP protocol implementation, SM2/SM3/SM4 cryptographic algorithms

---

## File Structure

### Modified Files
- `tool/transport_common.cc` - Add "tlcp" version string support
- `tool/client.cc` - Add TLCP parameters, parsing, and configuration
- `tool/server.cc` - Add TLCP parameters, parsing, and configuration

### New Files
- `tool/test/bssl_tlcp_test.cc` - Integration tests for TLCP functionality

---

## Task 1: Extend VersionFromString to support "tlcp"

**Files:**
- Modify: `tool/transport_common.cc:267-282`

- [ ] **Step 1: Write failing test**

Create test file `tool/test/version_test.cc`:

```cpp
#include <gtest/gtest.h>
#include "../transport_common.h"

TEST(VersionFromStringTest, SupportsTLCP) {
  uint16_t version;
  ASSERT_TRUE(VersionFromString(&version, "tlcp"));
  EXPECT_EQ(version, 0x0101);
}

TEST(VersionFromStringTest, TLCPCaseInsensitive) {
  uint16_t version;
  ASSERT_TRUE(VersionFromString(&version, "TLCP"));
  EXPECT_EQ(version, 0x0101);
}

TEST(VersionFromStringTest, ReturnsFalseForInvalidTLCP) {
  uint16_t version;
  EXPECT_FALSE(VersionFromString(&version, "tlcp1.0"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./tool_test --gtest_filter=VersionFromStringTest*`
Expected: FAIL with tests failing

- [ ] **Step 3: Modify VersionFromString to support "tlcp"**

In `tool/transport_common.cc`, modify the `VersionFromString` function (lines 267-282):

```cpp
bool VersionFromString(uint16_t *out_version, const std::string &version) {
  if (version == "tls1" || version == "tls1.0") {
    *out_version = TLS1_VERSION;
    return true;
  } else if (version == "tls1.1") {
    *out_version = TLS1_1_VERSION;
    return true;
  } else if (version == "tls1.2") {
    *out_version = TLS1_2_VERSION;
    return true;
  } else if (version == "tls1.3") {
    *out_version = TLS1_3_VERSION;
    return true;
  } else if (strcasecmp(version.c_str(), "tlcp") == 0) {
    *out_version = 0x0101;  // TLCP_VERSION
    return true;
  }
  return false;
}
```

Add include for strcasecmp at top of file:
```cpp
#include <strings.h>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd build && ./tool_test --gtest_filter=VersionFromStringTest*`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tool/transport_common.cc tool/test/version_test.cc
git commit -m "tool: add tlcp version string support to VersionFromString"
```

---

## Task 2: Add TLCP arguments to client.cc

**Files:**
- Modify: `tool/client.cc:39-212` (kArguments array)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
#include <gtest/gtest.h>
#include "../../tool/client.cc"

// Note: This will be a functional test that verifies argument parsing
// by calling Client() with test arguments and checking behavior
TEST(BSSLTLCPTest, RejectsTLCPParametersWithoutTLCPFlag) {
  // This test will verify that TLCP parameters without -tlcp flag fail
  // Implementation will check error output
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL or compile error (functionality not implemented)

- [ ] **Step 3: Add TLCP parameters to kArguments array**

In `tool/client.cc`, add TLCP arguments to the `kArguments` array (after line 211, before the empty entry):

```cpp
    {
        "-tlcp",
        kBooleanArgument,
        "Enable TLCP mode",
    },
    {
        "-tlcp-sign-cert",
        kOptionalArgument,
        "PEM file containing the TLCP signing certificate",
    },
    {
        "-tlcp-sign-key",
        kOptionalArgument,
        "PEM file containing the TLCP signing private key",
    },
    {
        "-tlcp-enc-cert",
        kOptionalArgument,
        "PEM file containing the TLCP encryption certificate",
    },
    {
        "-tlcp-enc-key",
        kOptionalArgument,
        "PEM file containing the TLCP encryption private key",
    },
```

- [ ] **Step 4: Run client to verify arguments are recognized**

Run: `./build/bssl client -help`
Expected: TLCP arguments appear in help output

- [ ] **Step 5: Commit**

```bash
git add tool/client.cc
git commit -m "tool: add TLCP argument definitions to client"
```

---

## Task 3: Add TLCP arguments to server.cc

**Files:**
- Modify: `tool/server.cc:30-121` (kArguments array)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
TEST(BSSLTLCPTest, ServerRejectsTLCPParametersWithoutTLCPFlag) {
  // This test will verify that server TLCP parameters without -tlcp flag fail
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL or compile error

- [ ] **Step 3: Add TLCP parameters to kArguments array**

In `tool/server.cc`, add TLCP arguments to the `kArguments` array (after line 116, before the empty entry):

```cpp
    {
        "-tlcp",
        kBooleanArgument,
        "Enable TLCP mode",
    },
    {
        "-tlcp-sign-cert",
        kOptionalArgument,
        "PEM file containing the TLCP signing certificate",
    },
    {
        "-tlcp-sign-key",
        kOptionalArgument,
        "PEM file containing the TLCP signing private key",
    },
    {
        "-tlcp-enc-cert",
        kOptionalArgument,
        "PEM file containing the TLCP encryption certificate",
    },
    {
        "-tlcp-enc-key",
        kOptionalArgument,
        "PEM file containing the TLCP encryption private key",
    },
```

- [ ] **Step 4: Run server to verify arguments are recognized**

Run: `./build/bssl server -help`
Expected: TLCP arguments appear in help output

- [ ] **Step 5: Commit**

```bash
git add tool/server.cc
git commit -m "tool: add TLCP argument definitions to server"
```

---

## Task 4: Add TLCP parameter validation to client.cc

**Files:**
- Modify: `tool/client.cc:427-649` (Client function)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
TEST(BSSLTLCPTest, ClientRejectsTLCPWithoutSignCert) {
  std::vector<std::string> args = {
    "client", "-tlcp", "-tlcp-sign-key", "key.pem",
    "-tlcp-enc-cert", "enc.pem", "-tlcp-enc-key", "enc.key",
    "-connect", "localhost:8443"
  };
  EXPECT_FALSE(Client(args));
  // Check stderr for error message
}

TEST(BSSLTLCPTest, ClientRejectsTLCPWithoutEncCert) {
  std::vector<std::string> args = {
    "client", "-tlcp", "-tlcp-sign-cert", "sign.pem",
    "-tlcp-sign-key", "sign.key", "-tlcp-enc-key", "enc.key",
    "-connect", "localhost:8443"
  };
  EXPECT_FALSE(Client(args));
}

TEST(BSSLTLCPTest, ClientRejectsTLCPParametersWithoutTLCPFlag) {
  std::vector<std::string> args = {
    "client", "-tlcp-sign-cert", "sign.pem",
    "-tlcp-sign-key", "sign.key", "-tlcp-enc-cert", "enc.pem",
    "-tlcp-enc-key", "enc.key", "-connect", "localhost:8443"
  };
  EXPECT_FALSE(Client(args));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL (validation not implemented)

- [ ] **Step 3: Add TLCP parameter validation function**

In `tool/client.cc`, add helper function before the Client function (around line 400):

```cpp
static bool ValidateTLCPParameters(
    const std::map<std::string, std::string> &args_map,
    std::string *error_msg) {
  bool has_tlcp = args_map.count("-tlcp") != 0;
  bool has_any_tlcp_param =
      args_map.count("-tlcp-sign-cert") != 0 ||
      args_map.count("-tlcp-sign-key") != 0 ||
      args_map.count("-tlcp-enc-cert") != 0 ||
      args_map.count("-tlcp-enc-key") != 0;

  if (!has_tlcp && has_any_tlcp_param) {
    *error_msg = "TLCP parameters require -tlcp flag";
    return false;
  }

  if (has_tlcp) {
    if (args_map.count("-tlcp-sign-cert") == 0) {
      *error_msg = "-tlcp-sign-cert is required when using -tlcp";
      return false;
    }
    if (args_map.count("-tlcp-sign-key") == 0) {
      *error_msg = "-tlcp-sign-key is required when using -tlcp";
      return false;
    }
    if (args_map.count("-tlcp-enc-cert") == 0) {
      *error_msg = "-tlcp-enc-cert is required when using -tlcp";
      return false;
    }
    if (args_map.count("-tlcp-enc-key") == 0) {
      *error_msg = "-tlcp-enc-key is required when using -tlcp";
      return false;
    }
  }

  return true;
}
```

- [ ] **Step 4: Call validation in Client function**

In `tool/client.cc`, after `ParseKeyValueArguments` call (around line 437), add:

```cpp
  std::string error_msg;
  if (!ValidateTLCPParameters(args_map, &error_msg)) {
    fprintf(stderr, "%s\n", error_msg.c_str());
    return false;
  }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd build && ./bssl_tlcp_test`
Expected: PASS for validation tests

- [ ] **Step 6: Commit**

```bash
git add tool/client.cc tool/test/bssl_tlcp_test.cc
git commit -m "tool: add TLCP parameter validation to client"
```

---

## Task 5: Add TLCP parameter validation to server.cc

**Files:**
- Modify: `tool/server.cc:253-453` (Server function)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
TEST(BSSLTLCPTest, ServerRejectsTLCPWithoutSignCert) {
  std::vector<std::string> args = {
    "server", "-tlcp", "-tlcp-sign-key", "key.pem",
    "-tlcp-enc-cert", "enc.pem", "-tlcp-enc-key", "enc.key",
    "-accept", "8443"
  };
  EXPECT_FALSE(Server(args));
}

TEST(BSSLTLCPTest, ServerRejectsTLCPWithoutEncCert) {
  std::vector<std::string> args = {
    "server", "-tlcp", "-tlcp-sign-cert", "sign.pem",
    "-tlcp-sign-key", "sign.key", "-tlcp-enc-key", "enc.key",
    "-accept", "8443"
  };
  EXPECT_FALSE(Server(args));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL (validation not implemented)

- [ ] **Step 3: Add TLCP parameter validation function**

In `tool/server.cc`, add helper function before the Server function (around line 250):

```cpp
static bool ValidateTLCPParameters(
    const std::map<std::string, std::string> &args_map,
    std::string *error_msg) {
  bool has_tlcp = args_map.count("-tlcp") != 0;
  bool has_any_tlcp_param =
      args_map.count("-tlcp-sign-cert") != 0 ||
      args_map.count("-tlcp-sign-key") != 0 ||
      args_map.count("-tlcp-enc-cert") != 0 ||
      args_map.count("-tlcp-enc-key") != 0;

  if (!has_tlcp && has_any_tlcp_param) {
    *error_msg = "TLCP parameters require -tlcp flag";
    return false;
  }

  if (has_tlcp) {
    if (args_map.count("-tlcp-sign-cert") == 0) {
      *error_msg = "-tlcp-sign-cert is required when using -tlcp";
      return false;
    }
    if (args_map.count("-tlcp-sign-key") == 0) {
      *error_msg = "-tlcp-sign-key is required when using -tlcp";
      return false;
    }
    if (args_map.count("-tlcp-enc-cert") == 0) {
      *error_msg = "-tlcp-enc-cert is required when using -tlcp";
      return false;
    }
    if (args_map.count("-tlcp-enc-key") == 0) {
      *error_msg = "-tlcp-enc-key is required when using -tlcp";
      return false;
    }
  }

  return true;
}
```

- [ ] **Step 4: Call validation in Server function**

In `tool/server.cc`, after `ParseKeyValueArguments` call (around line 263), add:

```cpp
  std::string error_msg;
  if (!ValidateTLCPParameters(args_map, &error_msg)) {
    fprintf(stderr, "%s\n", error_msg.c_str());
    return false;
  }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd build && ./bssl_tlcp_test`
Expected: PASS for server validation tests

- [ ] **Step 6: Commit**

```bash
git add tool/server.cc tool/test/bssl_tlcp_test.cc
git commit -m "tool: add TLCP parameter validation to server"
```

---

## Task 6: Configure client with TLCP method

**Files:**
- Modify: `tool/client.cc:439-450` (SSL_CTX creation section)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
TEST(BSSLTLCPTest, ClientUsesTLCPMethodWhenEnabled) {
  // This test will verify that when -tlcp is specified,
  // the SSL_CTX is created with TLCP_client_method()
  // This may require mocking or a functional test approach
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL (TLCP method not selected)

- [ ] **Step 3: Add TLCP include and modify SSL_CTX creation**

In `tool/client.cc`, add TLCP include at top (after line with `#include <openssl/ssl.h>`):

```cpp
#include <openssl/tlcp.h>
```

Modify SSL_CTX creation section (around line 439):

```cpp
  bssl::UniquePtr<SSL_CTX> ctx;
  if (args_map.count("-tlcp") != 0) {
    ctx.reset(SSL_CTX_new(TLCP_client_method()));
  } else {
    ctx.reset(SSL_CTX_new(TLS_method()));
  }
  if (!ctx) {
    fprintf(stderr, "Failed to create SSL_CTX\n");
    return false;
  }
```

- [ ] **Step 4: Set default cipher for TLCP**

After SSL_CTX creation, add cipher configuration (around line 450):

```cpp
  if (args_map.count("-tlcp") != 0) {
    // Set default cipher for TLCP if not specified
    if (args_map.count("-cipher") == 0) {
      if (!SSL_CTX_set_strict_cipher_list(ctx.get(),
                                         "ECC-SM2-SM4-CBC-SM3")) {
        fprintf(stderr, "Failed setting TLCP cipher list\n");
        return false;
      }
    }
  }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd build && ./bssl_tlcp_test`
Expected: PASS (functional verification will come later)

- [ ] **Step 6: Commit**

```bash
git add tool/client.cc tool/test/bssl_tlcp_test.cc
git commit -m "tool: configure client to use TLCP method when enabled"
```

---

## Task 7: Configure server with TLCP method

**Files:**
- Modify: `tool/server.cc:265-276` (SSL_CTX creation section)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
TEST(BSSLTLCPTest, ServerUsesTLCPMethodWhenEnabled) {
  // This test will verify that when -tlcp is specified,
  // the SSL_CTX is created with TLCP_server_method()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL (TLCP method not selected)

- [ ] **Step 3: Add TLCP include and modify SSL_CTX creation**

In `tool/server.cc`, add TLCP include at top (after line with `#include <openssl/ssl.h>`):

```cpp
#include <openssl/tlcp.h>
```

Modify SSL_CTX creation section (around line 265):

```cpp
  bssl::UniquePtr<SSL_CTX> ctx;
  if (args_map.count("-tlcp") != 0) {
    ctx.reset(SSL_CTX_new(TLCP_server_method()));
  } else {
    ctx.reset(SSL_CTX_new(TLS_method()));
  }
  if (!ctx) {
    fprintf(stderr, "Failed to create SSL_CTX\n");
    return false;
  }
```

- [ ] **Step 4: Set default cipher for TLCP**

After SSL_CTX creation, add cipher configuration (around line 275):

```cpp
  if (args_map.count("-tlcp") != 0) {
    // Set default cipher for TLCP if not specified
    if (args_map.count("-cipher") == 0) {
      if (!SSL_CTX_set_strict_cipher_list(ctx.get(),
                                         "ECC-SM2-SM4-CBC-SM3")) {
        fprintf(stderr, "Failed setting TLCP cipher list\n");
        return false;
      }
    }
  }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd build && ./bssl_tlcp_test`
Expected: PASS (functional verification will come later)

- [ ] **Step 6: Commit**

```bash
git add tool/server.cc tool/test/bssl_tlcp_test.cc
git commit -m "tool: configure server to use TLCP method when enabled"
```

---

## Task 8: Load dual certificates in client

**Files:**
- Modify: `tool/client.cc:544-558` (certificate loading section)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
TEST(BSSLTLCPTest, ClientLoadsTLCPDualCertificates) {
  // This test will verify that client loads encryption certificate
  // when TLCP is enabled
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL (dual certificate loading not implemented)

- [ ] **Step 3: Add TLCP certificate loading**

Inver `tool/client.cc`, add certificate loading after existing certificate handling (around line 558), before session cache setup:

```cpp
  // TLCP dual certificate handling
  if (args_map.count("-tlcp") != 0) {
    // Load encryption certificate and key for TLCP client
    const std::string &enc_key_file = args_map["-tlcp-enc-key"];
    const std::string &enc_cert_file =
        args_map.count("-tlcp-enc-cert") != 0
        ? args_map["-tlcp-enc-cert"]
        : enc_key_file;

    if (!SSL_CTX_use_PrivateKey_file(ctx.get(), enc_key_file.c_str(),
                                     SSL_FILETYPE_PEM)) {
      fprintf(stderr, "Failed to load TLCP encryption key: %s\n",
              enc_key_file.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }

    if (!SSL_CTX_use_certificate_chain_file(ctx.get(), enc_cert_file.c_str())) {
      fprintf(stderr, "Failed to load TLCP encryption cert: %s\n",
              enc_cert_file.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }

    if (!SSL_CTX_check_private_key(ctx.get())) {
      fprintf(stderr,
              "TLCP encryption certificate and key do not match\n");
      return false;
    }
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd build && ./bssl_tlcp_test`
Expected: PASS (requires test certificates)

- [ ] **Step 5: Commit**

```bash
git add tool/client.cc tool/test/bssl_tlcp_test.cc
git commit -m "tool: load TLCP encryption certificates in client"
```

---

## Task 9: Load dual certificates in server

**Files:**
- Modify: `tool/server.cc:278-310` (certificate loading section)

- [ ] **Step 1: Write failing test**

Add to `tool/test/bssl_tlcp_test.cc`:

```cpp
TEST(BSSLTLCPTest, ServerLoadsTLCPDualCertificates) {
  // This test will verify that server loads both signing and
  // encryption certificates when TLCP is enabled
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd build && ./bssl_tlcp_test`
Expected: FAIL (dual certificate loading not implemented)

- [ ] **Step 3: Add TLCP certificate loading**

In `tool/server.cc`, after the existing certificate loading section (around line 310), add:

```cpp
  // TLCP dual certificate handling
  if (args_map.count("-tlcp") != 0) {
    // Load signing certificate and key
    const std::string &sign_key_file = args_map["-tlcp-sign-key"];
    const std::string &sign_cert_file = args_map["-tlcp-sign-cert"];

    bssl::UniquePtr<EVP_PKEY> sign_pkey(LoadPrivateKey(sign_key_file));
    if (!sign_pkey) {
      fprintf(stderr, "Failed to load TLCP signing key: %s\n",
              sign_key_file.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }

    bssl::UniquePtr<X509> sign_cert(LoadCertificate(sign_cert_file));
    if (!sign_cert) {
      fprintf(stderr, "Failed to load TLCP signing cert: %s\n",
              sign_cert_file.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }

    if (!SSL_CTX_use_tlcp_sign_certificate(ctx.get(), sign_cert.get(),
                                            sign_pkey.get())) {
      fprintf(stderr, "Failed to set TLCP signing certificate\n");
      ERR_print_errors_fp(stderr);
      return false;
    }

    // Load encryption certificate and key
    const std::string &enc_key_file = args_map["-tlcp-enc-key"];
    const std::string &enc_cert_file = args_map["-tlcp-enc-cert"];

    bssl::UniquePtr<EVP_PKEY> enc_penc_pkey(LoadPrivateKey(enc_key_file));
    if (!enc_penc_pkey) {
      fprintf(stderr, "Failed to load TLCP encryption key: %s\n",
              enc_key_file.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }

    bssl::UniquePtr<X509> enc_cert(LoadCertificate(enc_cert_file));
    if (!enc_cert) {
      fprintf(stderr, "Failed to load TLCP encryption cert: %s\n",
              enc_cert_file.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }

    if (!SSL_CTX_use_tlcp_enc_certificate(ctx.get(), enc_cert.get(),
                                           enc_penc_pkey.get())) {
      fprintf(stderr, "Failed to set TLCP encryption certificate\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
  }
```

Note: Need to add LoadCertificate helper function similar to LoadPrivateKey:

```cpp
static bssl::UniquePtr<X509> LoadCertificate(const std::string &file) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_file()));
  if (!bio || !BIO_read_filename(bio.get(), file.c_str())) {
    return nullptr;
  }
  bssl::UniquePtr<X509> x509(PEM_read_bio_X509(bio.get(), nullptr,
                                 nullptr, nullptr));
  return x509;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd build && ./bssl_tlcp_test`
Expected: PASS (requires test certificates)

- [ ] **Step 5: Commit**

```bash
git add tool/server.cc tool/test/bssl_tlcp_test.cc
git commit -m "tool: load TLCP dual certificates in server"
```

---

## Task 10: Write integration test for TLCP handshake

**Files:**
- Modify: `tool/test/bssl_tlcp_test.cc`

- [ ] **Step 1: Write test skeleton**

```cpp
#include <gtest/gtest.h>
#include <thread>
#include <vector>

extern bool Client(const std::vector<std::string> &args);
extern bool Server(const std::vector<std::string> &args);

TEST(BSSLTLCPTest, BasicTLCPHandshake) {
  // This test will:
  // 1. Start bssl server in a thread with TLCP enabled
  // 2. Connect bssl client with TLCP enabled
  // 3. Verify connection is successful

  // Note: Requires test certificates to be present
  // Will be implemented after certificate generation is available
}
```

- [ ] **Step 2: Create test certificate generation**

Create helper functions to generate test certificates (using existing SM2 tools):

```cpp
static bool GenerateTestCertificates() {
  // Use bssl sm2 tool to generate test certificates
  // This is a placeholder - actual implementation will use
  // existing certificate generation tools
  return true;
}

static void CleanupTestCertificates() {
  // Remove generated test certificates
}
```

- [ [ ] **Step 3: Implement basic handshake test**

```cpp
TEST(BSSLTLCPTest, BasicTLCPHandshake) {
  if (!GenerateTestCertificates()) {
    GTEST_SKIP() << "Could not generate test certificates";
  }

  std::thread server_thread([]() {
    std::vector<std::string> server_args = {
      "server", "-tlcp",
      "-tlcp-sign-cert", "server_sign.pem",
      "-tlcp-sign-key", "server_sign.key",
      "-tlcp-enc-cert", "server_enc.pem",
      "-tlcp-enc-key", "server_enc.key",
      "-accept", "18443"
    };
    Server(server_args);
  });

  // Give server time to start
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  std::vector<std::string> client_args = {
    "client", "-tlcp",
    "-tlcp-enc-cert", "client_enc.pem",
    "-tlcp-enc-key", "client_enc.key",
    "-connect", "localhost:18443"
  };

  bool result = Client(client_args);

  CleanupTestCertificates();

  EXPECT_TRUE(result);
}
```

- [ ] **Step 4: Run test to verify it works**

Run: `cd build && ./bssl_tlcp_test --gtest_filter=BSSLTLCPTest.BasicTLCPHandshake`
Expected: Server starts, client connects successfully

- [ ] **Step 5: Commit**

```bash
git add tool/test/bssl_tlcp_test.cc
git commit -m "tool: add TLCP basic handshake integration test"
```

---

## Task 11: Update build.json for new test files

**Files:**
- Modify: `build.json` (at repository root)

- [ ] **Step 1: Add test file to build.json**

Add `tool/test/bssl_tlcp_test.cc` to the appropriate test target in build.json

Search for existing tool test entries and add:

```json
"tool/test/bssl_tlcp_test.cc",
```

- [ ] **Step 2: Regenerate build files**

Run: `go run ./util/pregenerate`

- [ ] **Step 3: Rebuild**

Run: `cmake -GNinja -B build && ninja -C build`

- [ ] **Step 4: Commit**

```bash
git add build.json gen/
git commit -m "build: add bssl_tlcp_test to build configuration"
```

---

## Task 12: Final verification and documentation

- [ ] **Step 1: Run all tests**

Run: `ninja -C build run_tests`

Verify all tests pass including new TLCP tests.

- [ ] **Step 2: Manual testing**

Test client with TLCP:
```bash
./build/bssl client -tlcp \
  -tlcp-enc-cert client_enc.pem \
  -tlcp-enc-key client_enc.key \
  -connect localhost:18443
```

Test server with TLCP:
```bash
./build/bssl server -tlcp \
  -tlcp-sign-cert server_sign.pem \
  -tlcp-sign-key server_sign.key \
  -tlcp-enc-cert server_enc.pem \
  -tlcp-enc-key server_enc.key \
  -accept 18443
```

- [ ] **Step 3: Verify TLCP connection**

Establish connection and verify TLCP is being used (check logs/output).

- [ ] **Step 4: Final commit**

```bash
git add .
git commit -m "tool: complete TLCP support for bssl client and server"
```
