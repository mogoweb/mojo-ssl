// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/base.h>

#include <memory>
#include <string>
#include <vector>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/sm2.h>

#include "internal.h"


BSSL_NAMESPACE_BEGIN

// Helper to convert hex string to bytes (used for future hex input options)
#if 0
static bool HexToBytes(const std::string &hex, std::vector<uint8_t> *out) {
  if (hex.size() % 2 != 0) {
    fprintf(stderr, "Invalid hex string length (must be even).\n");
    return false;
  }

  out->resize(hex.size() / 2);
  for (size_t i = 0; i < out->size(); i++) {
    unsigned int byte;
    if (sscanf(hex.c_str() + i * 2, "%2x", &byte) != 1) {
      fprintf(stderr, "Invalid hex character at position %zu.\n", i * 2);
      return false;
    }
    (*out)[i] = static_cast<uint8_t>(byte);
  }
  return true;
}

// Helper to convert bytes to hex string
static std::string BytesToHex(const uint8_t *data, size_t len) {
  static const char kHexChars[] = "0123456789abcdef";
  std::string result;
  result.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    result.push_back(kHexChars[data[i] >> 4]);
    result.push_back(kHexChars[data[i] & 0xf]);
  }
  return result;
}
#endif

static ScopedFILE OpenInputFILE(const std::string &filename) {
  if (filename == "-") {
    return ScopedFILE(stdin);
  }

  ScopedFILE file(fopen(filename.c_str(), "rb"));
  if (!file) {
    fprintf(stderr, "Failed to open input file '%s': %s\n", filename.c_str(),
            strerror(errno));
    return ScopedFILE();
  }
  return file;
}

static ScopedFILE OpenOutputFILE(const std::string &filename) {
  if (filename.empty() || filename == "-") {
    return ScopedFILE(stdout);
  }

  ScopedFILE file(fopen(filename.c_str(), "wb"));
  if (!file) {
    fprintf(stderr, "Failed to open output file '%s': %s\n", filename.c_str(),
            strerror(errno));
    return ScopedFILE();
  }
  return file;
}

// Write EC key to PEM file
static bool WriteKeyToPEM(EC_KEY *key, const std::string &filename, bool is_private) {
  ScopedFILE file(fopen(filename.c_str(), "w"));
  if (!file) {
    fprintf(stderr, "Failed to open output file '%s': %s\n", filename.c_str(),
            strerror(errno));
    return false;
  }

  if (is_private) {
    if (!PEM_write_ECPrivateKey(file.get(), key, nullptr, nullptr, 0, nullptr, nullptr)) {
      fprintf(stderr, "Failed to write private key.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
  } else {
    if (!PEM_write_EC_PUBKEY(file.get(), key)) {
      fprintf(stderr, "Failed to write public key.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
  }

  return true;
}

// Read EC key from PEM file
static bssl::UniquePtr<EC_KEY> ReadKeyFromPEM(const std::string &filename, bool is_private) {
  ScopedFILE file(fopen(filename.c_str(), "r"));
  if (!file) {
    fprintf(stderr, "Failed to open key file '%s': %s\n", filename.c_str(),
            strerror(errno));
    return nullptr;
  }

  bssl::UniquePtr<EC_KEY> key;
  if (is_private) {
    key.reset(PEM_read_ECPrivateKey(file.get(), nullptr, nullptr, nullptr));
  } else {
    key.reset(PEM_read_EC_PUBKEY(file.get(), nullptr, nullptr, nullptr));
  }

  if (!key) {
    fprintf(stderr, "Failed to read %s key from '%s'.\n",
            is_private ? "private" : "public", filename.c_str());
    ERR_print_errors_fp(stderr);
    return nullptr;
  }

  return key;
}

static void PrintUsage(const char *name) {
  fprintf(stderr,
          "Usage: %s <command> [options]\n"
          "\n"
          "SM2 elliptic curve cryptography tool.\n"
          "\n"
          "Commands:\n"
          "  genkey           Generate SM2 key pair\n"
          "  encrypt          Encrypt with SM2 public key\n"
          "  decrypt          Decrypt with SM2 private key\n"
          "\n"
          "genkey options:\n"
          "  -out-private FILE    Output private key file (PEM format)\n"
          "  -out-public FILE     Output public key file (PEM format)\n"
          "\n"
          "encrypt options:\n"
          "  -in FILE             Input file to encrypt (default: stdin)\n"
          "  -out FILE            Output file (default: stdout)\n"
          "  -pubkey FILE         Public key file (PEM format)\n"
          "\n"
          "decrypt options:\n"
          "  -in FILE             Input file to decrypt (default: stdin)\n"
          "  -out FILE            Output file (default: stdout)\n"
          "  -privkey FILE        Private key file (PEM format)\n"
          "\n"
          "Examples:\n"
          "  # Generate key pair\n"
          "  %s genkey -out-private sm2_priv.pem -out-public sm2_pub.pem\n"
          "\n"
          "  # Encrypt a file\n"
          "  %s encrypt -pubkey sm2_pub.pem -in plaintext.txt -out ciphertext.bin\n"
          "\n"
          "  # Decrypt a file\n"
          "  %s decrypt -privkey sm2_priv.pem -in ciphertext.bin -out plaintext.txt\n",
          name, name, name, name);
}

// SM2 key generation
static bool SM2GenKey(const std::vector<std::string> &args) {
  std::string private_key_file, public_key_file;

  for (size_t i = 0; i < args.size(); i++) {
    const std::string &arg = args[i];

    if ((arg == "-out-private" || arg == "-out-private-key") && i + 1 < args.size()) {
      private_key_file = args[++i];
    } else if ((arg == "-out-public" || arg == "-out-public-key") && i + 1 < args.size()) {
      public_key_file = args[++i];
    } else if (arg[0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", arg.c_str());
      return false;
    }
  }

  if (private_key_file.empty() && public_key_file.empty()) {
    fprintf(stderr, "Error: At least one output file (-out-private or -out-public) is required.\n");
    return false;
  }

  // Create SM2 key
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  if (!key) {
    fprintf(stderr, "Failed to create SM2 key structure.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (!SM2_generate_key(key.get())) {
    fprintf(stderr, "Failed to generate SM2 key pair.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  // Write private key
  if (!private_key_file.empty()) {
    if (!WriteKeyToPEM(key.get(), private_key_file, true)) {
      return false;
    }
    printf("Private key written to: %s\n", private_key_file.c_str());
  }

  // Write public key
  if (!public_key_file.empty()) {
    if (!WriteKeyToPEM(key.get(), public_key_file, false)) {
      return false;
    }
    printf("Public key written to: %s\n", public_key_file.c_str());
  }

  return true;
}

// SM2 encryption
static bool SM2Encrypt(const std::vector<std::string> &args) {
  std::string input_file = "-", output_file, pubkey_file;

  for (size_t i = 0; i < args.size(); i++) {
    const std::string &arg = args[i];

    if ((arg == "-in" || arg == "-input") && i + 1 < args.size()) {
      input_file = args[++i];
    } else if ((arg == "-out" || arg == "-output") && i + 1 < args.size()) {
      output_file = args[++i];
    } else if ((arg == "-pubkey" || arg == "-public-key") && i + 1 < args.size()) {
      pubkey_file = args[++i];
    } else if (arg[0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", arg.c_str());
      return false;
    }
  }

  if (pubkey_file.empty()) {
    fprintf(stderr, "Error: Public key file is required. Use -pubkey option.\n");
    return false;
  }

  // Read public key
  bssl::UniquePtr<EC_KEY> key = ReadKeyFromPEM(pubkey_file, false);
  if (!key) {
    return false;
  }

  // Verify it's an SM2 key
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  if (!group || EC_GROUP_get_curve_name(group) != NID_sm2) {
    fprintf(stderr, "Error: The public key is not an SM2 key.\n");
    return false;
  }

  // Read input data
  ScopedFILE in_file = OpenInputFILE(input_file);
  if (!in_file) {
    return false;
  }

  std::vector<uint8_t> plaintext;
  if (!ReadAll(&plaintext, in_file.get())) {
    fprintf(stderr, "Failed to read input file.\n");
    return false;
  }

  // Encrypt
  size_t ciphertext_len = SM2_ciphertext_size(plaintext.size());
  std::vector<uint8_t> ciphertext(ciphertext_len);

  if (!SM2_encrypt(key.get(), plaintext.data(), plaintext.size(),
                   ciphertext.data(), &ciphertext_len)) {
    fprintf(stderr, "SM2 encryption failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  // Write output
  ScopedFILE out_file = OpenOutputFILE(output_file);
  if (!out_file) {
    return false;
  }

  if (fwrite(ciphertext.data(), 1, ciphertext_len, out_file.get()) != ciphertext_len) {
    fprintf(stderr, "Failed to write output: %s\n", strerror(errno));
    return false;
  }

  return true;
}

// SM2 decryption
static bool SM2Decrypt(const std::vector<std::string> &args) {
  std::string input_file = "-", output_file, privkey_file;

  for (size_t i = 0; i < args.size(); i++) {
    const std::string &arg = args[i];

    if ((arg == "-in" || arg == "-input") && i + 1 < args.size()) {
      input_file = args[++i];
    } else if ((arg == "-out" || arg == "-output") && i + 1 < args.size()) {
      output_file = args[++i];
    } else if ((arg == "-privkey" || arg == "-private-key") && i + 1 < args.size()) {
      privkey_file = args[++i];
    } else if (arg[0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", arg.c_str());
      return false;
    }
  }

  if (privkey_file.empty()) {
    fprintf(stderr, "Error: Private key file is required. Use -privkey option.\n");
    return false;
  }

  // Read private key
  bssl::UniquePtr<EC_KEY> key = ReadKeyFromPEM(privkey_file, true);
  if (!key) {
    return false;
  }

  // Verify it's an SM2 key
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  if (!group || EC_GROUP_get_curve_name(group) != NID_sm2) {
    fprintf(stderr, "Error: The private key is not an SM2 key.\n");
    return false;
  }

  // Read input data
  ScopedFILE in_file = OpenInputFILE(input_file);
  if (!in_file) {
    return false;
  }

  std::vector<uint8_t> ciphertext;
  if (!ReadAll(&ciphertext, in_file.get())) {
    fprintf(stderr, "Failed to read input file.\n");
    return false;
  }

  // Decrypt
  size_t plaintext_len = SM2_plaintext_size(ciphertext.size());
  if (plaintext_len == 0) {
    plaintext_len = ciphertext.size();  // Use full size as buffer
  }
  std::vector<uint8_t> plaintext(plaintext_len);
  plaintext_len = plaintext.size();  // Reset to buffer size

  if (!SM2_decrypt(key.get(), ciphertext.data(), ciphertext.size(),
                   plaintext.data(), &plaintext_len)) {
    fprintf(stderr, "SM2 decryption failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  // Write output
  ScopedFILE out_file = OpenOutputFILE(output_file);
  if (!out_file) {
    return false;
  }

  if (fwrite(plaintext.data(), 1, plaintext_len, out_file.get()) != plaintext_len) {
    fprintf(stderr, "Failed to write output: %s\n", strerror(errno));
    return false;
  }

  return true;
}

bool SM2Tool(const std::vector<std::string> &args) {
  if (args.empty()) {
    PrintUsage("sm2");
    return false;
  }

  const std::string &command = args[0];
  std::vector<std::string> sub_args(args.begin() + 1, args.end());

  if (command == "genkey") {
    return SM2GenKey(sub_args);
  } else if (command == "encrypt") {
    return SM2Encrypt(sub_args);
  } else if (command == "decrypt") {
    return SM2Decrypt(sub_args);
  } else if (command == "-h" || command == "--help" || command == "help") {
    PrintUsage("sm2");
    return true;
  } else {
    fprintf(stderr, "Unknown command: %s\n", command.c_str());
    PrintUsage("sm2");
    return false;
  }
}

BSSL_NAMESPACE_END
