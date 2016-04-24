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

#include <openssl/rand.h>

#include "internal.h"


/* It's assumed that the operating system always has an unfailing source of
 * entropy which is accessed via |CRYPTO_sysrand|. (If the operating system
 * entropy source fails, it's up to |CRYPTO_sysrand| to abort the process—we
 * don't try to handle it.)
 *
 * We assume that the OS entropy is safe from fork()ing and VM duplication.
 * This might be a bit of a leap of faith, esp on Windows, but there's nothing
 * that we can do about it.
 *
 * In addition, the hardware may provide a low-latency RNG. Intel's rdrand
 * instruction is the canonical example of this. When a hardware RNG is
 * available we don't need to worry about an RNG failure arising from fork()ing
 * the process or moving a VM, so we can keep thread-local RNG state and XOR
 * the hardware entropy in. (Support for this was in BoringSSL, but it was
 * removed.) */

int RAND_bytes(uint8_t *buf, size_t len) {
  CRYPTO_sysrand(buf, len);
  return 1;
}
