/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2005 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/ssl.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "../crypto/internal.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

DTLS1_STATE::DTLS1_STATE()
    : has_change_cipher_spec(false),
      outgoing_messages_complete(false),
      flight_has_reply(false),
      handshake_write_overflow(false),
      handshake_read_overflow(false),
      sending_flight(false),
      sending_ack(false),
      queued_key_update(QueuedKeyUpdate::kNone) {}

DTLS1_STATE::~DTLS1_STATE() {}

bool DTLS1_STATE::Init() {
  // Set up the initial epochs.
  read_epoch.aead = SSLAEADContext::CreateNullCipher();
  write_epoch.aead = SSLAEADContext::CreateNullCipher();
  if (read_epoch.aead == nullptr || write_epoch.aead == nullptr) {
    return false;
  }

  return true;
}

bool dtls1_new(SSL *ssl) {
  if (!tls_new(ssl)) {
    return false;
  }
  UniquePtr<DTLS1_STATE> d1 = MakeUnique<DTLS1_STATE>();
  if (!d1 || !d1->Init()) {
    tls_free(ssl);
    return false;
  }

  ssl->d1 = d1.release();
  return true;
}

void dtls1_free(SSL *ssl) {
  tls_free(ssl);

  if (ssl == NULL) {
    return;
  }

  Delete(ssl->d1);
  ssl->d1 = NULL;
}

void DTLSTimer::StartMicroseconds(OPENSSL_timeval now, uint64_t microseconds) {
  uint64_t seconds = microseconds / 1000000;
  microseconds %= 1000000;

  now.tv_usec += microseconds;
  if (now.tv_usec >= 1000000) {
    now.tv_usec -= 1000000;
    seconds++;
  }

  if (now.tv_sec > UINT64_MAX - seconds) {
    Stop();
    return;
  }
  now.tv_sec += seconds;
  expire_time_ = now;
}

void DTLSTimer::Stop() { expire_time_ = {0, 0}; }

bool DTLSTimer::IsExpired(OPENSSL_timeval now) const {
  return MicrosecondsRemaining(now) == 0;
}

bool DTLSTimer::IsSet() const {
  return expire_time_.tv_sec != 0 || expire_time_.tv_usec != 0;
}

uint64_t DTLSTimer::MicrosecondsRemaining(OPENSSL_timeval now) const {
  if (!IsSet()) {
    return kNever;
  }

  if (now.tv_sec > expire_time_.tv_sec ||
      (now.tv_sec == expire_time_.tv_sec &&
       now.tv_usec >= expire_time_.tv_usec)) {
    return 0;
  }

  uint64_t sec = expire_time_.tv_sec - now.tv_sec;
  uint32_t usec;
  if (expire_time_.tv_usec >= now.tv_usec) {
    usec = expire_time_.tv_usec - now.tv_usec;
  } else {
    sec--;
    usec = expire_time_.tv_usec + 1000000 - now.tv_usec;
  }

  // If remaining time is less than 15 ms, return 0 to prevent issues because of
  // small divergences with socket timeouts.
  if (sec == 0 && usec < 15000) {
    return 0;
  }

  if (sec > UINT64_MAX / 1000000) {
    return kNever;
  }
  sec *= 1000000;
  if (sec > UINT64_MAX - usec) {
    return kNever;
  }
  return sec + usec;
}

void dtls1_stop_timer(SSL *ssl) {
  ssl->d1->num_timeouts = 0;
  ssl->d1->retransmit_timer.Stop();
  ssl->d1->timeout_duration_ms = ssl->initial_timeout_duration_ms;
}

BSSL_NAMESPACE_END

using namespace bssl;

void DTLSv1_set_initial_timeout_duration(SSL *ssl, uint32_t duration_ms) {
  ssl->initial_timeout_duration_ms = duration_ms;
}

int DTLSv1_get_timeout(const SSL *ssl, struct timeval *out) {
  if (!SSL_is_dtls(ssl)) {
    return 0;
  }

  OPENSSL_timeval now = ssl_ctx_get_current_time(ssl->ctx.get());
  uint64_t remaining_usec =
      ssl->d1->retransmit_timer.MicrosecondsRemaining(now);
  remaining_usec =
      std::min(remaining_usec, ssl->d1->ack_timer.MicrosecondsRemaining(now));
  if (remaining_usec == DTLSTimer::kNever) {
    return 0;  // No timeout is set.
  }

  uint64_t remaining_sec = remaining_usec / 1000000;
  remaining_usec %= 1000000;

  // |timeval| uses |time_t|, which may be 32-bit.
  const auto kTvSecMax = std::numeric_limits<decltype(out->tv_sec)>::max();
  if (remaining_sec > static_cast<uint64_t>(kTvSecMax)) {
    out->tv_sec = kTvSecMax;  // Saturate the output.
    out->tv_usec = 999999;
  } else {
    out->tv_sec = static_cast<decltype(out->tv_sec)>(remaining_sec);
  }
  out->tv_usec = remaining_usec;
  return 1;
}

int DTLSv1_handle_timeout(SSL *ssl) {
  ssl_reset_error_state(ssl);

  if (!SSL_is_dtls(ssl)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return -1;
  }

  if (!ssl->d1->ack_timer.IsSet() && !ssl->d1->retransmit_timer.IsSet()) {
    // No timers are running. Don't bother querying the clock.
    return 0;
  }

  OPENSSL_timeval now = ssl_ctx_get_current_time(ssl->ctx.get());
  bool any_timer_expired = false;
  if (ssl->d1->ack_timer.IsExpired(now)) {
    any_timer_expired = true;
    ssl->d1->sending_ack = true;
    ssl->d1->ack_timer.Stop();
  }

  if (ssl->d1->retransmit_timer.IsExpired(now)) {
    any_timer_expired = true;
    ssl->d1->sending_flight = true;
    ssl->d1->retransmit_timer.Stop();

    ssl->d1->num_timeouts++;
    // Reduce MTU after 2 unsuccessful retransmissions.
    if (ssl->d1->num_timeouts > DTLS1_MTU_TIMEOUTS &&
        !(SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU)) {
      long mtu = BIO_ctrl(ssl->wbio.get(), BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0,
                          nullptr);
      if (mtu >= 0 && mtu <= (1 << 30) && (unsigned)mtu >= dtls1_min_mtu()) {
        ssl->d1->mtu = (unsigned)mtu;
      }
    }
  }

  if (!any_timer_expired) {
    return 0;
  }

  return dtls1_flush(ssl);
}
