/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "file_test.h"

#include <algorithm>
#include <memory>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

#include "../internal.h"


FileTest::FileTest(const char *path) {
  file_ = fopen(path, "r");
  if (file_ == nullptr) {
    fprintf(stderr, "Could not open file %s: %s.\n", path, strerror(errno));
  }
}

FileTest::~FileTest() {
  if (file_ != nullptr) {
    fclose(file_);
  }
}

// FindDelimiter returns a pointer to the first '=' or ':' in |str| or nullptr
// if there is none.
static const char *FindDelimiter(const char *str) {
  while (*str) {
    if (*str == ':' || *str == '=') {
      return str;
    }
    str++;
  }
  return nullptr;
}

// StripSpace returns a string containing up to |len| characters from |str| with
// leading and trailing whitespace removed.
static std::string StripSpace(const char *str, size_t len) {
  // Remove leading space.
  while (len > 0 && isspace(*str)) {
    str++;
    len--;
  }
  while (len > 0 && isspace(str[len - 1])) {
    len--;
  }
  return std::string(str, len);
}

static std::pair<std::string, std::string> ParseKeyValue(const char *str, const size_t len) {
  const char *delimiter = FindDelimiter(str);
  std::string key, value;
  if (delimiter == nullptr) {
    key = StripSpace(str, len);
  } else {
    key = StripSpace(str, delimiter - str);
    value = StripSpace(delimiter + 1, str + len - delimiter - 1);
  }
  return {key, value};
}

FileTest::ReadResult FileTest::ReadNext() {
  // If the previous test had unused attributes or instructions, it is an error.
  if (!unused_attributes_.empty() && !ignore_unused_attributes_) {
    for (const std::string &key : unused_attributes_) {
      PrintLine("Unused attribute: %s", key.c_str());
    }
    return kReadError;
  }
  if (!unused_instructions_.empty() && !ignore_unused_attributes_) {
    for (const std::string &key : unused_instructions_) {
      PrintLine("Unused instruction: %s", key.c_str());
    }
    return kReadError;
  }

  ClearTest();

  static const size_t kBufLen = 8192 * 4;
  std::unique_ptr<char[]> buf(new char[kBufLen]);

  bool in_instruction_block = false;
  is_at_new_instruction_block_ = false;

  while (true) {
    // Read the next line.
    if (fgets(buf.get(), kBufLen, file_) == nullptr) {
      if (feof(file_)) {
        // EOF is a valid terminator for a test.
        return start_line_ > 0 ? kReadSuccess : kReadEOF;
      }
      fprintf(stderr, "Error reading from input.\n");
      return kReadError;
    }

    line_++;
    size_t len = strlen(buf.get());
    // Check for truncation.
    if (len > 0 && buf[len - 1] != '\n' && !feof(file_)) {
      fprintf(stderr, "Line %u too long.\n", line_);
      return kReadError;
    }

    if (buf[0] == '\n' || buf[0] == '\r' || buf[0] == '\0') {
      // Empty lines delimit tests.
      if (start_line_ > 0) {
        return kReadSuccess;
      }
      if (in_instruction_block) {
        in_instruction_block = false;
        // Delimit instruction block from test with a blank line.
        current_test_ += "\r\n";
      }
    } else if (buf[0] == '#' ||
               strcmp("[B.4.2 Key Pair Generation by Testing Candidates]\r\n",
                      buf.get()) == 0) {
      // Ignore comments. The above instruction-like line is treated as a
      // comment because the FIPS lab's request files are hopelessly
      // inconsistent.
    } else if (buf[0] == '[') {  // Inside an instruction block.
      is_at_new_instruction_block_ = true;
      if (start_line_ != 0) {
        // Instructions should be separate blocks.
        fprintf(stderr, "Line %u is an instruction in a test case.\n", line_);
        return kReadError;
      }
      if (!in_instruction_block) {
        ClearInstructions();
        in_instruction_block = true;
      }

      // Parse the line as an instruction ("[key = value]" or "[key]").
      std::string kv = StripSpace(buf.get(), len);
      if (kv[kv.size() - 1] != ']') {
        fprintf(stderr, "Line %u, invalid instruction: %s\n", line_,
                kv.c_str());
        return kReadError;
      }
      current_test_ += kv + "\r\n";
      kv = std::string(kv.begin() + 1, kv.end() - 1);

      for (;;) {
        size_t idx = kv.find(",");
        if (idx == std::string::npos) {
          idx = kv.size();
        }
        std::string key, value;
        std::tie(key, value) = ParseKeyValue(kv.c_str(), idx);
        instructions_[key] = value;
        if (idx == kv.size())
          break;
        kv = kv.substr(idx + 1);
      }
    } else {
      // Parsing a test case.
      if (in_instruction_block) {
        // Some NIST CAVP test files (TDES) have a test case immediately
        // following an instruction block, without a separate blank line, some
        // of the time.
        in_instruction_block = false;
      }

      current_test_ += std::string(buf.get(), len);
      std::string key, value;
      std::tie(key, value) = ParseKeyValue(buf.get(), len);

      // Duplicate keys are rewritten to have “/2”, “/3”, … suffixes.
      std::string mapped_key = key;
      for (unsigned i = 2; attributes_.count(mapped_key) != 0; i++) {
        char suffix[32];
        snprintf(suffix, sizeof(suffix), "/%u", i);
        suffix[sizeof(suffix)-1] = 0;
        mapped_key = key + suffix;
      }

      unused_attributes_.insert(mapped_key);
      attributes_[mapped_key] = value;
      if (start_line_ == 0) {
        // This is the start of a test.
        type_ = mapped_key;
        parameter_ = value;
        start_line_ = line_;
        for (const auto &kv : instructions_) {
          unused_instructions_.insert(kv.first);
        }
      }
    }
  }
}

void FileTest::PrintLine(const char *format, ...) {
  va_list args;
  va_start(args, format);

  fprintf(stderr, "Line %u: ", start_line_);
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");

  va_end(args);
}

const std::string &FileTest::GetType() {
  OnKeyUsed(type_);
  return type_;
}

const std::string &FileTest::GetParameter() {
  OnKeyUsed(type_);
  return parameter_;
}

bool FileTest::HasAttribute(const std::string &key) {
  OnKeyUsed(key);
  return attributes_.count(key) > 0;
}

bool FileTest::GetAttribute(std::string *out_value, const std::string &key) {
  OnKeyUsed(key);
  auto iter = attributes_.find(key);
  if (iter == attributes_.end()) {
    PrintLine("Missing attribute '%s'.", key.c_str());
    return false;
  }
  *out_value = iter->second;
  return true;
}

const std::string &FileTest::GetAttributeOrDie(const std::string &key) {
  if (!HasAttribute(key)) {
    abort();
  }
  return attributes_[key];
}

bool FileTest::HasInstruction(const std::string &key) {
  OnInstructionUsed(key);
  return instructions_.count(key) > 0;
}

bool FileTest::GetInstruction(std::string *out_value, const std::string &key) {
  OnInstructionUsed(key);
  auto iter = instructions_.find(key);
  if (iter == instructions_.end()) {
    PrintLine("Missing instruction '%s'.", key.c_str());
    return false;
  }
  *out_value = iter->second;
  return true;
}

const std::string &FileTest::CurrentTestToString() const {
  return current_test_;
}

static bool FromHexDigit(uint8_t *out, char c) {
  if ('0' <= c && c <= '9') {
    *out = c - '0';
    return true;
  }
  if ('a' <= c && c <= 'f') {
    *out = c - 'a' + 10;
    return true;
  }
  if ('A' <= c && c <= 'F') {
    *out = c - 'A' + 10;
    return true;
  }
  return false;
}

bool FileTest::GetBytes(std::vector<uint8_t> *out, const std::string &key) {
  std::string value;
  if (!GetAttribute(&value, key)) {
    return false;
  }

  if (value.size() >= 2 && value[0] == '"' && value[value.size() - 1] == '"') {
    out->assign(value.begin() + 1, value.end() - 1);
    return true;
  }

  if (value.size() % 2 != 0) {
    PrintLine("Error decoding value: %s", value.c_str());
    return false;
  }
  out->clear();
  out->reserve(value.size() / 2);
  for (size_t i = 0; i < value.size(); i += 2) {
    uint8_t hi, lo;
    if (!FromHexDigit(&hi, value[i]) || !FromHexDigit(&lo, value[i + 1])) {
      PrintLine("Error decoding value: %s", value.c_str());
      return false;
    }
    out->push_back((hi << 4) | lo);
  }
  return true;
}

static std::string EncodeHex(const uint8_t *in, size_t in_len) {
  static const char kHexDigits[] = "0123456789abcdef";
  std::string ret;
  ret.reserve(in_len * 2);
  for (size_t i = 0; i < in_len; i++) {
    ret += kHexDigits[in[i] >> 4];
    ret += kHexDigits[in[i] & 0xf];
  }
  return ret;
}

bool FileTest::ExpectBytesEqual(const uint8_t *expected, size_t expected_len,
                                const uint8_t *actual, size_t actual_len) {
  if (expected_len == actual_len &&
      OPENSSL_memcmp(expected, actual, expected_len) == 0) {
    return true;
  }

  std::string expected_hex = EncodeHex(expected, expected_len);
  std::string actual_hex = EncodeHex(actual, actual_len);
  PrintLine("Expected: %s", expected_hex.c_str());
  PrintLine("Actual:   %s", actual_hex.c_str());
  return false;
}

void FileTest::ClearTest() {
  start_line_ = 0;
  type_.clear();
  parameter_.clear();
  attributes_.clear();
  unused_attributes_.clear();
  current_test_ = "";
}

void FileTest::ClearInstructions() {
  instructions_.clear();
  unused_attributes_.clear();
}

void FileTest::OnKeyUsed(const std::string &key) {
  unused_attributes_.erase(key);
}

void FileTest::OnInstructionUsed(const std::string &key) {
  unused_instructions_.erase(key);
}

bool FileTest::IsAtNewInstructionBlock() const {
  return is_at_new_instruction_block_;
}

void FileTest::InjectInstruction(const std::string &key,
                                 const std::string &value) {
  instructions_[key] = value;
}

void FileTest::SetIgnoreUnusedAttributes(bool ignore) {
  ignore_unused_attributes_ = ignore;
}

int FileTestMainSilent(FileTestFunc run_test, void *arg, const char *path) {
  FileTest t(path);
  if (!t.is_open()) {
    return 1;
  }

  bool failed = false;
  while (true) {
    FileTest::ReadResult ret = t.ReadNext();
    if (ret == FileTest::kReadError) {
      return 1;
    } else if (ret == FileTest::kReadEOF) {
      break;
    }

    bool result = run_test(&t, arg);
    if (t.HasAttribute("Error")) {
      if (result) {
        t.PrintLine("Operation unexpectedly succeeded.");
        failed = true;
        continue;
      }
      uint32_t err = ERR_peek_error();
      if (ERR_reason_error_string(err) != t.GetAttributeOrDie("Error")) {
        t.PrintLine("Unexpected error; wanted '%s', got '%s'.",
                    t.GetAttributeOrDie("Error").c_str(),
                    ERR_reason_error_string(err));
        failed = true;
        ERR_clear_error();
        continue;
      }
      ERR_clear_error();
    } else if (!result) {
      // In case the test itself doesn't print output, print something so the
      // line number is reported.
      t.PrintLine("Test failed");
      ERR_print_errors_fp(stderr);
      failed = true;
      continue;
    }
  }

  return failed ? 1 : 0;
}

int FileTestMain(FileTestFunc run_test, void *arg, const char *path) {
  int result = FileTestMainSilent(run_test, arg, path);
  if (!result) {
    printf("PASS\n");
  }
  return result;
}
