/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#ifndef OPENSSL_HEADER_OBJECTS_H
#define OPENSSL_HEADER_OBJECTS_H

#include <openssl/base.h>

#include <openssl/bytestring.h>
#include <openssl/obj_mac.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* OBJ_cbs2nid returns the nid corresponding to the DER data in |cbs|, or
 * |NID_undef| if no such object is known. */
OPENSSL_EXPORT int OBJ_cbs2nid(const CBS *cbs);

/* OBJ_sn2nid returns the nid corresponding to |short_name|, or |NID_undef| if
 * no such short name is known. */
OPENSSL_EXPORT int OBJ_sn2nid(const char *short_name);

/* OBJ_ln2nid returns the nid corresponding to |long_name|, or |NID_undef| if
 * no such long name is known. */
OPENSSL_EXPORT int OBJ_ln2nid(const char *long_name);

/* OBJ_txt2nid returns the nid corresponding to |s|, which may be a short name,
 * long name, or an ASCII string containing a dotted sequence of numbers. It
 * returns the nid or NID_undef if unknown. */
OPENSSL_EXPORT int OBJ_txt2nid(const char *s);


/* Getting information about nids. */

/* OBJ_nid2sn returns the short name for |nid|, or NULL if |nid| is unknown. */
OPENSSL_EXPORT const char *OBJ_nid2sn(int nid);

/* OBJ_nid2sn returns the long name for |nid|, or NULL if |nid| is unknown. */
OPENSSL_EXPORT const char *OBJ_nid2ln(int nid);

/* Adding objects at runtime. */

/* OBJ_create adds a known object and returns the nid of the new object, or
 * NID_undef on error. */
OPENSSL_EXPORT int OBJ_create(const char *oid, const char *short_name,
                              const char *long_name);


/* Handling signature algorithm identifiers.
 *
 * Some NIDs (e.g. sha256WithRSAEncryption) specify both a digest algorithm and
 * a public key algorithm. The following functions map between pairs of digest
 * and public-key algorithms and the NIDs that specify their combination.
 *
 * Sometimes the combination NID leaves the digest unspecified (e.g.
 * rsassaPss). In these cases, the digest NID is |NID_undef|. */

/* OBJ_find_sigid_algs finds the digest and public-key NIDs that correspond to
 * the signing algorithm |sign_nid|. If successful, it sets |*out_digest_nid|
 * and |*out_pkey_nid| and returns one. Otherwise it returns zero. Any of
 * |out_digest_nid| or |out_pkey_nid| can be NULL if the caller doesn't need
 * that output value. */
OPENSSL_EXPORT int OBJ_find_sigid_algs(int sign_nid, int *out_digest_nid,
                                       int *out_pkey_nid);

/* OBJ_find_sigid_by_algs finds the signature NID that corresponds to the
 * combination of |digest_nid| and |pkey_nid|. If success, it sets
 * |*out_sign_nid| and returns one. Otherwise it returns zero. The
 * |out_sign_nid| argument can be NULL if the caller only wishes to learn
 * whether the combination is valid. */
OPENSSL_EXPORT int OBJ_find_sigid_by_algs(int *out_sign_nid, int digest_nid,
                                          int pkey_nid);


#if defined(__cplusplus)
}  /* extern C */
#endif

#define OBJ_R_UNKNOWN_NID 100

#endif  /* OPENSSL_HEADER_OBJECTS_H */
