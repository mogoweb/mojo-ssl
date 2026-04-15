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

#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/sm4.h>

#include "internal.h"


BSSL_NAMESPACE_BEGIN

static const char kStdinName[] = "standard input";

static void PrintUsage(const char *name) {
  fprintf(stderr,
          "Usage: %s [options] [file...]\n"
          "\n"
          "SM4 encryption/decryption tool.\n"
          "\n"
          "Options:\n"
          "  -d, --decrypt          Decrypt mode (default is encrypt)\n"
          "  -k, --key HEXKEY       128-bit key in hex (32 hex chars)\n"
          "  -i, --iv HEXIV         IV in hex (32 hex chars, required for CBC/CTR/OFB/CFB)\n"
          "  -m, --mode MODE        Cipher mode: ecb, cbc, ctr, ofb, cfb (default: cbc)\n"
          "  -o, --output FILE      Output file (default: stdout)\n"
          "  -h, --help             Show this help message\n"
          "\n"
          "Examples:\n"
          "  # Encrypt with CBC mode\n"
          "  %s -k 0123456789abcdeffedcba9876543210 -i 0123456789abcdeffedcba9876543210 -m cbc input.txt\n"
          "\n"
          "  # Decrypt\n"
          "  %s -d -k 0123456789abcdeffedcba9876543210 -i 0123456789abcdeffedcba9876543210 -m cbc encrypted.bin\n"
          "\n"
          "  # Encrypt from stdin\n"
          "  echo 'hello' | %s -k 0123456789abcdeffedcba9876543210 -i 0123456789abcdeffedcba9876543210\n",
          name, name, name, name);
}

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

static bool ProcessFile(FILE *in_file, FILE *out_file, const EVP_CIPHER *cipher,
                        const uint8_t *key, const uint8_t *iv, bool encrypt) {
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    fprintf(stderr, "Failed to create cipher context.\n");
    return false;
  }

  if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key, iv, encrypt ? 1 : 0)) {
    fprintf(stderr, "Failed to initialize cipher.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  static const size_t kBufSize = 8192;
  auto in_buf = std::make_unique<uint8_t[]>(kBufSize);
  auto out_buf = std::make_unique<uint8_t[]>(kBufSize + EVP_MAX_BLOCK_LENGTH);

  for (;;) {
    size_t n = fread(in_buf.get(), 1, kBufSize, in_file);
    if (n == 0) {
      if (ferror(in_file)) {
        fprintf(stderr, "Failed to read input: %s\n", strerror(errno));
        return false;
      }
      break;  // EOF
    }

    int out_len;
    if (!EVP_CipherUpdate(ctx.get(), out_buf.get(), &out_len, in_buf.get(), n)) {
      fprintf(stderr, "Cipher update failed.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }

    if (out_len > 0) {
      if (fwrite(out_buf.get(), 1, out_len, out_file) != static_cast<size_t>(out_len)) {
        fprintf(stderr, "Failed to write output: %s\n", strerror(errno));
        return false;
      }
    }
  }

  int out_len;
  if (!EVP_CipherFinal_ex(ctx.get(), out_buf.get(), &out_len)) {
    fprintf(stderr, "Cipher final failed (data may be corrupted or wrong key/IV).\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (out_len > 0) {
    if (fwrite(out_buf.get(), 1, out_len, out_file) != static_cast<size_t>(out_len)) {
      fprintf(stderr, "Failed to write output: %s\n", strerror(errno));
      return false;
    }
  }

  return true;
}

bool SM4Cipher(const std::vector<std::string> &args) {
  bool decrypt = false;
  std::string key_hex, iv_hex, mode_str = "cbc", output_file;
  std::vector<std::string> input_files;
  bool show_help = false;

  // Parse arguments
  for (size_t i = 0; i < args.size(); i++) {
    const std::string &arg = args[i];

    if (arg == "-h" || arg == "--help") {
      show_help = true;
    } else if (arg == "-d" || arg == "--decrypt") {
      decrypt = true;
    } else if ((arg == "-k" || arg == "--key") && i + 1 < args.size()) {
      key_hex = args[++i];
    } else if ((arg == "-i" || arg == "--iv") && i + 1 < args.size()) {
      iv_hex = args[++i];
    } else if ((arg == "-m" || arg == "--mode") && i + 1 < args.size()) {
      mode_str = args[++i];
    } else if ((arg == "-o" || arg == "--output") && i + 1 < args.size()) {
      output_file = args[++i];
    } else if (arg[0] != '-') {
      input_files.push_back(arg);
    } else {
      fprintf(stderr, "Unknown option: %s\n", arg.c_str());
      PrintUsage("sm4");
      return false;
    }
  }

  if (show_help) {
    PrintUsage("sm4");
    return true;
  }

  if (key_hex.empty()) {
    fprintf(stderr, "Error: Key is required. Use -k or --key option.\n");
    PrintUsage("sm4");
    return false;
  }

  // Parse key
  std::vector<uint8_t> key;
  if (!HexToBytes(key_hex, &key)) {
    return false;
  }

  if (key.size() != 16) {
    fprintf(stderr, "Error: Key must be 128 bits (16 bytes, 32 hex chars).\n");
    return false;
  }

  // Parse IV
  std::vector<uint8_t> iv;
  if (!iv_hex.empty()) {
    if (!HexToBytes(iv_hex, &iv)) {
      return false;
    }
    if (iv.size() != 16) {
      fprintf(stderr, "Error: IV must be 128 bits (16 bytes, 32 hex chars).\n");
      return false;
    }
  }

  // Get cipher mode
  const EVP_CIPHER *cipher = nullptr;
  bool needs_iv = true;

  if (mode_str == "ecb") {
    cipher = EVP_sm4_ecb();
    needs_iv = false;
  } else if (mode_str == "cbc") {
    cipher = EVP_sm4_cbc();
  } else if (mode_str == "ctr") {
    cipher = EVP_sm4_ctr();
  } else if (mode_str == "ofb") {
    cipher = EVP_sm4_ofb();
  } else if (mode_str == "cfb") {
    cipher = EVP_sm4_cfb();
  } else {
    fprintf(stderr, "Error: Unknown mode '%s'. Valid modes: ecb, cbc, ctr, ofb, cfb\n",
            mode_str.c_str());
    return false;
  }

  if (needs_iv && iv.empty()) {
    fprintf(stderr, "Error: IV is required for %s mode. Use -i or --iv option.\n",
            mode_str.c_str());
    return false;
  }

  // Default to stdin if no input files
  if (input_files.empty()) {
    input_files.push_back("-");
  }

  // Open output file once
  ScopedFILE out_file = OpenOutputFILE(output_file);
  if (!out_file) {
    return false;
  }

  // Process each input file
  for (const auto &input_file : input_files) {
    ScopedFILE in_file = OpenInputFILE(input_file);
    if (!in_file) {
      return false;
    }

    if (!ProcessFile(in_file.get(), out_file.get(), cipher, key.data(),
                     iv.empty() ? nullptr : iv.data(), !decrypt)) {
      fprintf(stderr, "Failed to process %s\n",
              input_file == "-" ? kStdinName : input_file.c_str());
      return false;
    }
  }

  return true;
}

BSSL_NAMESPACE_END
