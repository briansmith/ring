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
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

$code.=<<___;
#include "openssl/arm_arch.h"

.text
.arch	armv8-a+crypto

.globl	GFp_memcmp
.type	GFp_memcmp,%function
.align	4
GFp_memcmp:
	eor	w3,w3,w3
	cbz	x2,.Lno_data	// len==0?
.Loop_cmp:
	ldrb	w4,[x0],#1
	ldrb	w5,[x1],#1
	eor	w4,w4,w5
	orr	w3,w3,w4
	subs	x2,x2,#1
	b.ne	.Loop_cmp

.Lno_data:
	neg	w0,w3
	lsr	w0,w0,#31
	ret
.size	GFp_memcmp,.-GFp_memcmp
___

print $code;
close STDOUT;
