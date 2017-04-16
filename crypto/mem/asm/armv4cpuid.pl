#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.

# /* ====================================================================
#  * Copyright (c) 1998-2017 The OpenSSL Project.  All rights reserved.
#  *
#  * Redistribution and use in source and binary forms, with or without
#  * modification, are permitted provided that the following conditions
#  * are met:
#  *
#  * 1. Redistributions of source code must retain the above copyright
#  *    notice, this list of conditions and the following disclaimer. 
#  *
#  * 2. Redistributions in binary form must reproduce the above copyright
#  *    notice, this list of conditions and the following disclaimer in
#  *    the documentation and/or other materials provided with the
#  *    distribution.
#  *
#  * 3. All advertising materials mentioning features or use of this
#  *    software must display the following acknowledgment:
#  *    "This product includes software developed by the OpenSSL Project
#  *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
#  *
#  * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
#  *    endorse or promote products derived from this software without
#  *    prior written permission. For written permission, please contact
#  *    openssl-core@openssl.org.
#  *
#  * 5. Products derived from this software may not be called "OpenSSL"
#  *    nor may "OpenSSL" appear in their names without prior written
#  *    permission of the OpenSSL Project.
#  *
#  * 6. Redistributions of any form whatsoever must retain the following
#  *    acknowledgment:
#  *    "This product includes software developed by the OpenSSL Project
#  *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
#  *
#  * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
#  * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#  * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
#  * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#  * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#  * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
#  * OF THE POSSIBILITY OF SUCH DAMAGE.
#  * ====================================================================
#  *
#  * This product includes cryptographic software written by Eric Young
#  * (eay@cryptsoft.com).  This product includes software written by Tim
#  * Hudson (tjh@cryptsoft.com).
#  *
#  */
# 
#  Original SSLeay License
#  -----------------------
# 
# /* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
#  * All rights reserved.
#  *
#  * This package is an SSL implementation written
#  * by Eric Young (eay@cryptsoft.com).
#  * The implementation was written so as to conform with Netscapes SSL.
#  * 
#  * This library is free for commercial and non-commercial use as long as
#  * the following conditions are aheared to.  The following conditions
#  * apply to all code found in this distribution, be it the RC4, RSA,
#  * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
#  * included with this distribution is covered by the same copyright terms
#  * except that the holder is Tim Hudson (tjh@cryptsoft.com).
#  * 
#  * Copyright remains Eric Young's, and as such any Copyright notices in
#  * the code are not to be removed.
#  * If this package is used in a product, Eric Young should be given attribution
#  * as the author of the parts of the library used.
#  * This can be in the form of a textual message at program startup or
#  * in documentation (online or textual) provided with the package.
#  * 
#  * Redistribution and use in source and binary forms, with or without
#  * modification, are permitted provided that the following conditions
#  * are met:
#  * 1. Redistributions of source code must retain the copyright
#  *    notice, this list of conditions and the following disclaimer.
#  * 2. Redistributions in binary form must reproduce the above copyright
#  *    notice, this list of conditions and the following disclaimer in the
#  *    documentation and/or other materials provided with the distribution.
#  * 3. All advertising materials mentioning features or use of this software
#  *    must display the following acknowledgement:
#  *    "This product includes cryptographic software written by
#  *     Eric Young (eay@cryptsoft.com)"
#  *    The word 'cryptographic' can be left out if the rouines from the library
#  *    being used are not cryptographic related :-).
#  * 4. If you include any Windows specific code (or a derivative thereof) from 
#  *    the apps directory (application code) you must include an acknowledgement:
#  *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
#  * 
#  * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
#  * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
#  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#  * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#  * SUCH DAMAGE.
#  * 
#  * The licence and distribution terms for any publically available version or
#  * derivative of this code cannot be changed.  i.e. this code cannot simply be
#  * copied and put under another distribution licence
#  * [including the GNU Public Licence.]
#  */


$flavour = shift;
$output  = shift;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

$code.=<<___;
#include "arm_arch.h"

.text
#if defined(__thumb2__) && !defined(__APPLE__)
.syntax	unified
.thumb
#else
.code	32
#undef	__thumb2__
#endif

.align	5
.global	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,%function
OPENSSL_atomic_add:
#if __ARM_ARCH__>=6
.Ladd:	ldrex	r2,[r0]
	add	r3,r2,r1
	strex	r2,r3,[r0]
	cmp	r2,#0
	bne	.Ladd
	mov	r0,r3
	bx	lr
#else
	stmdb	sp!,{r4-r6,lr}
	ldr	r2,.Lspinlock
	adr	r3,.Lspinlock
	mov	r4,r0
	mov	r5,r1
	add	r6,r3,r2	@ &spinlock
	b	.+8
.Lspin:	bl	sched_yield
	mov	r0,#-1
	swp	r0,r0,[r6]
	cmp	r0,#0
	bne	.Lspin

	ldr	r2,[r4]
	add	r2,r2,r5
	str	r2,[r4]
	str	r0,[r6]		@ release spinlock
	ldmia	sp!,{r4-r6,lr}
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_atomic_add,.-OPENSSL_atomic_add

.global	OPENSSL_cleanse
.type	OPENSSL_cleanse,%function
OPENSSL_cleanse:
	eor	ip,ip,ip
	cmp	r1,#7
#ifdef	__thumb2__
	itt	hs
#endif
	subhs	r1,r1,#4
	bhs	.Lot
	cmp	r1,#0
	beq	.Lcleanse_done
.Little:
	strb	ip,[r0],#1
	subs	r1,r1,#1
	bhi	.Little
	b	.Lcleanse_done

.Lot:	tst	r0,#3
	beq	.Laligned
	strb	ip,[r0],#1
	sub	r1,r1,#1
	b	.Lot
.Laligned:
	str	ip,[r0],#4
	subs	r1,r1,#4
	bhs	.Laligned
	adds	r1,r1,#4
	bne	.Little
.Lcleanse_done:
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_cleanse,.-OPENSSL_cleanse

.global	CRYPTO_memcmp
.type	CRYPTO_memcmp,%function
.align	4
CRYPTO_memcmp:
	eor	ip,ip,ip
	cmp	r2,#0
	beq	.Lno_data
	stmdb	sp!,{r4,r5}

.Loop_cmp:
	ldrb	r4,[r0],#1
	ldrb	r5,[r1],#1
	eor	r4,r4,r5
	orr	ip,ip,r4
	subs	r2,r2,#1
	bne	.Loop_cmp

	ldmia	sp!,{r4,r5}
.Lno_data:
	neg	r0,ip
	mov	r0,r0,lsr#31
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	CRYPTO_memcmp,.-CRYPTO_memcmp

#if __ARM_MAX_ARCH__>=7
.arch	armv7-a
.fpu	neon

.align	5
.global	_armv7_neon_probe
.type	_armv7_neon_probe,%function
_armv7_neon_probe:
	vorr	q0,q0,q0
	bx	lr
.size	_armv7_neon_probe,.-_armv7_neon_probe

.global	_armv7_tick
.type	_armv7_tick,%function
_armv7_tick:
#ifdef	__APPLE__
	mrrc	p15,0,r0,r1,c14		@ CNTPCT
#else
	mrrc	p15,1,r0,r1,c14		@ CNTVCT
#endif
	bx	lr
.size	_armv7_tick,.-_armv7_tick

.global	_armv8_aes_probe
.type	_armv8_aes_probe,%function
_armv8_aes_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
	.byte	0xb0,0xff,0x00,0x03	@ aese.8	q0,q0
#else
	.byte	0x00,0x03,0xb0,0xf3	@ aese.8	q0,q0
#endif
	bx	lr
.size	_armv8_aes_probe,.-_armv8_aes_probe

.global	_armv8_sha1_probe
.type	_armv8_sha1_probe,%function
_armv8_sha1_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
	.byte	0x00,0xef,0x40,0x0c	@ sha1c.32	q0,q0,q0
#else
	.byte	0x40,0x0c,0x00,0xf2	@ sha1c.32	q0,q0,q0
#endif
	bx	lr
.size	_armv8_sha1_probe,.-_armv8_sha1_probe

.global	_armv8_sha256_probe
.type	_armv8_sha256_probe,%function
_armv8_sha256_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
	.byte	0x00,0xff,0x40,0x0c	@ sha256h.32	q0,q0,q0
#else
	.byte	0x40,0x0c,0x00,0xf3	@ sha256h.32	q0,q0,q0
#endif
	bx	lr
.size	_armv8_sha256_probe,.-_armv8_sha256_probe
.global	_armv8_pmull_probe
.type	_armv8_pmull_probe,%function
_armv8_pmull_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
	.byte	0xa0,0xef,0x00,0x0e	@ vmull.p64	q0,d0,d0
#else
	.byte	0x00,0x0e,0xa0,0xf2	@ vmull.p64	q0,d0,d0
#endif
	bx	lr
.size	_armv8_pmull_probe,.-_armv8_pmull_probe
#endif

.global	OPENSSL_wipe_cpu
.type	OPENSSL_wipe_cpu,%function
OPENSSL_wipe_cpu:
#if __ARM_MAX_ARCH__>=7
	ldr	r0,.LOPENSSL_armcap
	adr	r1,.LOPENSSL_armcap
	ldr	r0,[r1,r0]
#ifdef	__APPLE__
	ldr	r0,[r0]
#endif
#endif
	eor	r2,r2,r2
	eor	r3,r3,r3
	eor	ip,ip,ip
#if __ARM_MAX_ARCH__>=7
	tst	r0,#1
	beq	.Lwipe_done
	veor	q0, q0, q0
	veor	q1, q1, q1
	veor	q2, q2, q2
	veor	q3, q3, q3
	veor	q8, q8, q8
	veor	q9, q9, q9
	veor	q10, q10, q10
	veor	q11, q11, q11
	veor	q12, q12, q12
	veor	q13, q13, q13
	veor	q14, q14, q14
	veor	q15, q15, q15
.Lwipe_done:
#endif
	mov	r0,sp
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_wipe_cpu,.-OPENSSL_wipe_cpu

.global	OPENSSL_instrument_bus
.type	OPENSSL_instrument_bus,%function
OPENSSL_instrument_bus:
	eor	r0,r0,r0
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_instrument_bus,.-OPENSSL_instrument_bus

.global	OPENSSL_instrument_bus2
.type	OPENSSL_instrument_bus2,%function
OPENSSL_instrument_bus2:
	eor	r0,r0,r0
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_instrument_bus2,.-OPENSSL_instrument_bus2

.align	5
#if __ARM_MAX_ARCH__>=7
.LOPENSSL_armcap:
.word	OPENSSL_armcap_P-.
#endif
#if __ARM_ARCH__>=6
.align	5
#else
.Lspinlock:
.word	atomic_add_spinlock-.Lspinlock
.align	5

.data
.align	2
atomic_add_spinlock:
.word	0
#endif

.comm	OPENSSL_armcap_P,4,4
.hidden	OPENSSL_armcap_P
___

print $code;
close STDOUT;
