/* Copyright (c) 2016, Google Inc.
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

#include <openssl/cpu.h>
#include <errno.h>

#ifdef __linux__

/* |getauxval| is not available on Android until API level 20. Link it as a weak
 * symbol and use other methods as fallback. As of Rust 1.14 this weak linkage
 * isn't supported, so we do it in C.
 */
unsigned long getauxval(unsigned long type) __attribute__((weak));

/*
 * If getauxval is not available, or an error occurs, return 0.
 * Otherwise, return the value found (which may be zero).
 */
unsigned long getauxval_wrapper(unsigned long type);

unsigned long getauxval_wrapper(unsigned long type) {
    if (getauxval == NULL) {
        return 0;
    }

    return getauxval(type);
}
#endif
