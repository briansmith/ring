/* Copyright (c) 2014, Google Inc.
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

#include <openssl/base.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "internal.h"
#include "transport_common.h"


static const struct argument kArguments[] = {
    {
        "-accept", kRequiredArgument,
        "The port of the server to bind on; eg 45102",
    },
    {
        "-cipher", kOptionalArgument,
        "An OpenSSL-style cipher suite string that configures the offered "
        "ciphers",
    },
    {
        "-max-version", kOptionalArgument,
        "The maximum acceptable protocol version",
    },
    {
        "-min-version", kOptionalArgument,
        "The minimum acceptable protocol version",
    },
    {
        "-key", kOptionalArgument,
        "PEM-encoded file containing the private key, leaf certificate and "
        "optional certificate chain. A self-signed certificate is generated "
        "at runtime if this argument is not provided.",
    },
    {
        "-ocsp-response", kOptionalArgument, "OCSP response file to send",
    },
    {
        "-loop", kBooleanArgument,
        "The server will continue accepting new sequential connections.",
    },
    {
        "", kOptionalArgument, "",
    },
};

static bool LoadOCSPResponse(SSL_CTX *ctx, const char *filename) {
  void *data = NULL;
  bool ret = false;
  size_t bytes_read;
  long length;

  FILE *f = fopen(filename, "rb");

  if (f == NULL ||
      fseek(f, 0, SEEK_END) != 0) {
    goto out;
  }

  length = ftell(f);
  if (length < 0) {
    goto out;
  }

  data = malloc(length);
  if (data == NULL) {
    goto out;
  }
  rewind(f);

  bytes_read = fread(data, 1, length, f);
  if (ferror(f) != 0 ||
      bytes_read != (size_t)length ||
      !SSL_CTX_set_ocsp_response(ctx, (uint8_t*)data, bytes_read)) {
    goto out;
  }

  ret = true;
out:
  if (f != NULL) {
      fclose(f);
  }
  free(data);
  return ret;
}

static bssl::UniquePtr<EVP_PKEY> MakeKeyPairForSelfSignedCert() {
  bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!ec_key || !EC_KEY_generate_key(ec_key.get())) {
    fprintf(stderr, "Failed to generate key pair.\n");
    return nullptr;
  }
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (!evp_pkey || !EVP_PKEY_assign_EC_KEY(evp_pkey.get(), ec_key.release())) {
    fprintf(stderr, "Failed to assign key pair.\n");
    return nullptr;
  }
  return evp_pkey;
}

static bssl::UniquePtr<X509> MakeSelfSignedCert(EVP_PKEY *evp_pkey,
                                                const int valid_days) {
  bssl::UniquePtr<X509> x509(X509_new());
  uint32_t serial;
  RAND_bytes(reinterpret_cast<uint8_t*>(&serial), sizeof(serial));
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), serial >> 1);
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), 60 * 60 * 24 * valid_days);

  X509_NAME* subject = X509_get_subject_name(x509.get());
  X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC,
                             reinterpret_cast<const uint8_t *>("US"), -1, -1,
                             0);
  X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                             reinterpret_cast<const uint8_t *>("BoringSSL"), -1,
                             -1, 0);
  X509_set_issuer_name(x509.get(), subject);

  if (!X509_set_pubkey(x509.get(), evp_pkey)) {
    fprintf(stderr, "Failed to set public key.\n");
    return nullptr;
  }
  if (!X509_sign(x509.get(), evp_pkey, EVP_sha256())) {
    fprintf(stderr, "Failed to sign certificate.\n");
    return nullptr;
  }
  return x509;
}

bool Server(const std::vector<std::string> &args) {
  if (!InitSocketLibrary()) {
    return false;
  }

  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  SSL_CTX_set_options(ctx.get(), SSL_OP_NO_SSLv3);

  // Server authentication is required.
  if (args_map.count("-key") != 0) {
    std::string key_file = args_map["-key"];
    if (!SSL_CTX_use_PrivateKey_file(ctx.get(), key_file.c_str(), SSL_FILETYPE_PEM)) {
      fprintf(stderr, "Failed to load private key: %s\n", key_file.c_str());
      return false;
    }
    if (!SSL_CTX_use_certificate_chain_file(ctx.get(), key_file.c_str())) {
      fprintf(stderr, "Failed to load cert chain: %s\n", key_file.c_str());
      return false;
    }
  } else {
    bssl::UniquePtr<EVP_PKEY> evp_pkey = MakeKeyPairForSelfSignedCert();
    if (!evp_pkey) {
      return false;
    }
    bssl::UniquePtr<X509> cert =
        MakeSelfSignedCert(evp_pkey.get(), 365 /* valid_days */);
    if (!cert) {
      return false;
    }
    if (!SSL_CTX_use_PrivateKey(ctx.get(), evp_pkey.get())) {
      fprintf(stderr, "Failed to set private key.\n");
      return false;
    }
    if (!SSL_CTX_use_certificate(ctx.get(), cert.get())) {
      fprintf(stderr, "Failed to set certificate.\n");
      return false;
    }
  }

  if (args_map.count("-cipher") != 0 &&
      !SSL_CTX_set_cipher_list(ctx.get(), args_map["-cipher"].c_str())) {
    fprintf(stderr, "Failed setting cipher list\n");
    return false;
  }

  if (args_map.count("-max-version") != 0) {
    uint16_t version;
    if (!VersionFromString(&version, args_map["-max-version"])) {
      fprintf(stderr, "Unknown protocol version: '%s'\n",
              args_map["-max-version"].c_str());
      return false;
    }
    if (!SSL_CTX_set_max_proto_version(ctx.get(), version)) {
      return false;
    }
  }

  if (args_map.count("-min-version") != 0) {
    uint16_t version;
    if (!VersionFromString(&version, args_map["-min-version"])) {
      fprintf(stderr, "Unknown protocol version: '%s'\n",
              args_map["-min-version"].c_str());
      return false;
    }
    if (!SSL_CTX_set_min_proto_version(ctx.get(), version)) {
      return false;
    }
  }

  if (args_map.count("-ocsp-response") != 0 &&
      !LoadOCSPResponse(ctx.get(), args_map["-ocsp-response"].c_str())) {
    fprintf(stderr, "Failed to load OCSP response: %s\n", args_map["-ocsp-response"].c_str());
    return false;
  }

  bool result = true;
  do {
    int sock = -1;
    if (!Accept(&sock, args_map["-accept"])) {
      return false;
    }

    BIO *bio = BIO_new_socket(sock, BIO_CLOSE);
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    SSL_set_bio(ssl.get(), bio, bio);

    int ret = SSL_accept(ssl.get());
    if (ret != 1) {
      int ssl_err = SSL_get_error(ssl.get(), ret);
      fprintf(stderr, "Error while connecting: %d\n", ssl_err);
      ERR_print_errors_cb(PrintErrorCallback, stderr);
      return false;
    }

    fprintf(stderr, "Connected.\n");
    PrintConnectionInfo(ssl.get());

    result = TransferData(ssl.get(), sock);
  } while (result && args_map.count("-loop") != 0);

  return result;
}
