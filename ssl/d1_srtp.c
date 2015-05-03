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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/*
  DTLS code by Eric Rescorla <ekr@rtfm.com>

  Copyright (C) 2006, Network Resonance, Inc.
  Copyright (C) 2011, RTFM, Inc.
*/

#include <stdio.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/obj.h>

#include "internal.h"
#include <openssl/srtp.h>


static const SRTP_PROTECTION_PROFILE srtp_known_profiles[] = {
    {
     "SRTP_AES128_CM_SHA1_80", SRTP_AES128_CM_SHA1_80,
    },
    {
     "SRTP_AES128_CM_SHA1_32", SRTP_AES128_CM_SHA1_32,
    },
    {0},
};

static int find_profile_by_name(const char *profile_name,
                                const SRTP_PROTECTION_PROFILE **pptr,
                                size_t len) {
  const SRTP_PROTECTION_PROFILE *p;

  p = srtp_known_profiles;
  while (p->name) {
    if (len == strlen(p->name) && !strncmp(p->name, profile_name, len)) {
      *pptr = p;
      return 1;
    }

    p++;
  }

  return 0;
}

static int find_profile_by_num(unsigned profile_num,
                               const SRTP_PROTECTION_PROFILE **pptr) {
  const SRTP_PROTECTION_PROFILE *p;

  p = srtp_known_profiles;
  while (p->name) {
    if (p->id == profile_num) {
      *pptr = p;
      return 1;
    }
    p++;
  }

  return 0;
}

static int ssl_ctx_make_profiles(const char *profiles_string,
                                 STACK_OF(SRTP_PROTECTION_PROFILE) **out) {
  STACK_OF(SRTP_PROTECTION_PROFILE) *profiles;

  const char *col;
  const char *ptr = profiles_string;

  profiles = sk_SRTP_PROTECTION_PROFILE_new_null();
  if (profiles == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_ctx_make_profiles,
                      SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES);
    return 0;
  }

  do {
    const SRTP_PROTECTION_PROFILE *p;

    col = strchr(ptr, ':');
    if (find_profile_by_name(ptr, &p, col ? col - ptr : strlen(ptr))) {
      sk_SRTP_PROTECTION_PROFILE_push(profiles, p);
    } else {
      OPENSSL_PUT_ERROR(SSL, ssl_ctx_make_profiles,
                        SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE);
      return 0;
    }

    if (col) {
      ptr = col + 1;
    }
  } while (col);

  *out = profiles;

  return 1;
}

int SSL_CTX_set_srtp_profiles(SSL_CTX *ctx, const char *profiles) {
  return ssl_ctx_make_profiles(profiles, &ctx->srtp_profiles);
}

int SSL_set_srtp_profiles(SSL *s, const char *profiles) {
  return ssl_ctx_make_profiles(profiles, &s->srtp_profiles);
}

STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *s) {
  if (s == NULL) {
    return NULL;
  }

  if (s->srtp_profiles != NULL) {
    return s->srtp_profiles;
  }

  if (s->ctx != NULL && s->ctx->srtp_profiles != NULL) {
    return s->ctx->srtp_profiles;
  }

  return NULL;
}

const SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s) {
  return s->srtp_profile;
}

int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles) {
  /* This API inverts its return value. */
  return !SSL_CTX_set_srtp_profiles(ctx, profiles);
}

int SSL_set_tlsext_use_srtp(SSL *s, const char *profiles) {
  /* This API inverts its return value. */
  return !SSL_set_srtp_profiles(s, profiles);
}

/* Note: this function returns 0 length if there are no profiles specified */
int ssl_add_clienthello_use_srtp_ext(SSL *s, uint8_t *p, int *len, int maxlen) {
  int ct = 0;
  int i;
  STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = 0;
  const SRTP_PROTECTION_PROFILE *prof;

  clnt = SSL_get_srtp_profiles(s);
  ct = sk_SRTP_PROTECTION_PROFILE_num(clnt); /* -1 if clnt == 0 */

  if (p) {
    if (ct == 0) {
      OPENSSL_PUT_ERROR(SSL, ssl_add_clienthello_use_srtp_ext,
                        SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST);
      return 0;
    }

    if (2 + ct * 2 + 1 > maxlen) {
      OPENSSL_PUT_ERROR(SSL, ssl_add_clienthello_use_srtp_ext,
                        SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG);
      return 0;
    }

    /* Add the length */
    s2n(ct * 2, p);
    for (i = 0; i < ct; i++) {
      prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);
      s2n(prof->id, p);
    }

    /* Add an empty use_mki value */
    *p++ = 0;
  }

  *len = 2 + ct * 2 + 1;

  return 1;
}

int ssl_parse_clienthello_use_srtp_ext(SSL *s, CBS *cbs, int *out_alert) {
  CBS profile_ids, srtp_mki;
  const SRTP_PROTECTION_PROFILE *cprof, *sprof;
  STACK_OF(SRTP_PROTECTION_PROFILE) *client_profiles = 0, *server_profiles;
  size_t i, j;
  int ret = 0;

  if (!CBS_get_u16_length_prefixed(cbs, &profile_ids) ||
      CBS_len(&profile_ids) < 2 ||
      !CBS_get_u8_length_prefixed(cbs, &srtp_mki) ||
      CBS_len(cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, ssl_parse_clienthello_use_srtp_ext,
                      SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    *out_alert = SSL_AD_DECODE_ERROR;
    goto done;
  }

  client_profiles = sk_SRTP_PROTECTION_PROFILE_new_null();
  if (client_profiles == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_parse_clienthello_use_srtp_ext,
                      ERR_R_MALLOC_FAILURE);
    *out_alert = SSL_AD_INTERNAL_ERROR;
    goto done;
  }

  while (CBS_len(&profile_ids) > 0) {
    uint16_t profile_id;

    if (!CBS_get_u16(&profile_ids, &profile_id)) {
      *out_alert = SSL_AD_DECODE_ERROR;
      goto done;
    }

    if (find_profile_by_num(profile_id, &cprof)) {
      sk_SRTP_PROTECTION_PROFILE_push(client_profiles, cprof);
    }
  }

  /* Discard the MKI value for now. */

  server_profiles = SSL_get_srtp_profiles(s);

  /* Pick the server's most preferred profile. */
  for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(server_profiles); i++) {
    sprof = sk_SRTP_PROTECTION_PROFILE_value(server_profiles, i);

    for (j = 0; j < sk_SRTP_PROTECTION_PROFILE_num(client_profiles); j++) {
      cprof = sk_SRTP_PROTECTION_PROFILE_value(client_profiles, j);

      if (cprof->id == sprof->id) {
        s->srtp_profile = sprof;
        ret = 1;
        goto done;
      }
    }
  }

  ret = 1;

done:
  if (client_profiles) {
    sk_SRTP_PROTECTION_PROFILE_free(client_profiles);
  }

  return ret;
}

int ssl_add_serverhello_use_srtp_ext(SSL *s, unsigned char *p, int *len,
                                     int maxlen) {
  if (p) {
    if (maxlen < 5) {
      OPENSSL_PUT_ERROR(SSL, ssl_add_serverhello_use_srtp_ext,
                        SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG);
      return 0;
    }

    if (s->srtp_profile == 0) {
      OPENSSL_PUT_ERROR(SSL, ssl_add_serverhello_use_srtp_ext,
                        SSL_R_USE_SRTP_NOT_NEGOTIATED);
      return 0;
    }

    s2n(2, p);
    s2n(s->srtp_profile->id, p);
    *p++ = 0;
  }

  *len = 5;

  return 1;
}

int ssl_parse_serverhello_use_srtp_ext(SSL *s, CBS *cbs, int *out_alert) {
  CBS profile_ids, srtp_mki;
  uint16_t profile_id;
  size_t i;

  STACK_OF(SRTP_PROTECTION_PROFILE) *client_profiles;
  const SRTP_PROTECTION_PROFILE *prof;

  /* The extension consists of a u16-prefixed profile ID list containing a
   * single uint16_t profile ID, then followed by a u8-prefixed srtp_mki field.
   *
   * See https://tools.ietf.org/html/rfc5764#section-4.1.1 */
  if (!CBS_get_u16_length_prefixed(cbs, &profile_ids) ||
      !CBS_get_u16(&profile_ids, &profile_id) || CBS_len(&profile_ids) != 0 ||
      !CBS_get_u8_length_prefixed(cbs, &srtp_mki) || CBS_len(cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, ssl_parse_serverhello_use_srtp_ext,
                      SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    *out_alert = SSL_AD_DECODE_ERROR;
    return 0;
  }

  if (CBS_len(&srtp_mki) != 0) {
    /* Must be no MKI, since we never offer one. */
    OPENSSL_PUT_ERROR(SSL, ssl_parse_serverhello_use_srtp_ext,
                      SSL_R_BAD_SRTP_MKI_VALUE);
    *out_alert = SSL_AD_ILLEGAL_PARAMETER;
    return 0;
  }

  client_profiles = SSL_get_srtp_profiles(s);

  /* Throw an error if the server gave us an unsolicited extension */
  if (client_profiles == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_parse_serverhello_use_srtp_ext,
                      SSL_R_NO_SRTP_PROFILES);
    *out_alert = SSL_AD_DECODE_ERROR;
    return 0;
  }

  /* Check to see if the server gave us something we support
     (and presumably offered). */
  for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(client_profiles); i++) {
    prof = sk_SRTP_PROTECTION_PROFILE_value(client_profiles, i);

    if (prof->id == profile_id) {
      s->srtp_profile = prof;
      *out_alert = 0;
      return 1;
    }
  }

  OPENSSL_PUT_ERROR(SSL, ssl_parse_serverhello_use_srtp_ext,
                    SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
  *out_alert = SSL_AD_ILLEGAL_PARAMETER;
  return 0;
}
