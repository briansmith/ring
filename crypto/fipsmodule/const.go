// Copyright (c) 2017, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

package main

// uninitHashValue is the default hash value that we inject into the module.
// This value need only be distinct, i.e. so that we can safely
// search-and-replace it in an object file.
var uninitHashValue = [32]byte{
	0x5f, 0x30, 0xd1, 0x80, 0xe7, 0x9e, 0x8f, 0x8f, 0xdf, 0x8b, 0x93, 0xd4, 0x96, 0x36, 0x30, 0xcc, 0x30, 0xea, 0x38, 0x0f, 0x75, 0x56, 0x9a, 0x1b, 0x23, 0x2f, 0x7c, 0x79, 0xff, 0x1b, 0x2b, 0xca,
}
