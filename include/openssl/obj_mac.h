/* THIS FILE IS GENERATED FROM objects.txt by objects.pl via the
 * following command:
 * perl objects.pl objects.txt obj_mac.num ../../include/openssl/obj_mac.h */

/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
 * [including the GNU Public Licence.]
 */

#define NID_undef 0

/* Digest algorithms */
#define NID_md5 4
#define NID_sha1 64
#define NID_sha256 672
#define NID_sha384 673
#define NID_sha512 674

/* ECDSA signature algorithms */
#define NID_ecdsa_with_SHA1 416
#define NID_ecdsa_with_Recommended 791
#define NID_ecdsa_with_Specified 792
#define NID_ecdsa_with_SHA256 794
#define NID_ecdsa_with_SHA384 795
#define NID_ecdsa_with_SHA512 796

/* RSA signature algorithms */
#define NID_md5WithRSAEncryption 8
#define NID_sha1WithRSAEncryption 65
#define NID_sha224WithRSAEncryption 671
#define NID_sha256WithRSAEncryption 668
#define NID_sha384WithRSAEncryption 669
#define NID_sha512WithRSAEncryption 670

/* ECC named curves */
#define NID_X9_62_prime256v1 415
#define NID_secp384r1 715

/* Ciphers */
#define NID_aes_128_cbc 419
#define NID_aes_128_ctr 904
#define NID_aes_128_gcm 895
#define NID_aes_256_cbc 427
#define NID_aes_256_ctr 906
#define NID_aes_256_gcm 901
#define NID_des_cbc 31
#define NID_des_ede_cbc 43
#define NID_des_ede3_cbc 44
