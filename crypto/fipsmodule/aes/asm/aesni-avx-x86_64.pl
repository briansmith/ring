#! /usr/bin/env perl
# Copyright 2009-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project.
# ====================================================================
#
# See aesni-x86_64.pl for more documentation.

$PREFIX="aes_hw";	# if $PREFIX is set to "AES", the script
			# generates drop-in replacement for
			# crypto/aes/asm/aes-x86_64.pl:-)

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$movkey = $PREFIX eq "aes_hw" ? "movups" : "movups";
@_4args=$win64?	("%rcx","%rdx","%r8", "%r9") :	# Win64 order
		("%rdi","%rsi","%rdx","%rcx");	# Unix order

$code=".text\n";


{ my ($inp,$bits,$key) = @_4args;
  $bits =~ s/%r/%e/;
# This is based on submission from Intel by
#	Huang Ying
#	Vinodh Gopal
#	Kahraman Akdemir
#
# Aggressively optimized in respect to aeskeygenassist's critical path
# and is contained in %xmm0-5 to meet Win64 ABI requirement.
#
# int ${PREFIX}_set_encrypt_key(const unsigned char *inp,
#				int bits, AES_KEY * const key);
#
# input:	$inp	user-supplied key
#		$bits	$inp length in bits
#		$key	pointer to key schedule
# output:	%eax	0 denoting success, -1 or -2 - failure (see C)
#		$bits	rounds-1 (used in aesni_set_decrypt_key)
#		*$key	key schedule
#		$key	pointer to key schedule (used in
#			aesni_set_decrypt_key)
#
# Subroutine is frame-less, which means that only volatile registers
# are used. Note that it's declared "abi-omnipotent", which means that
# amount of volatile registers is smaller on Windows.
#
# There are two variants of this function, one which uses aeskeygenassist
# ("base") and one which uses aesenclast + pshufb ("alt"). See aes/internal.h
# for details.
$code.=<<___;
.globl	${PREFIX}_set_encrypt_key_alt
.type	${PREFIX}_set_encrypt_key_alt,\@abi-omnipotent
.align	16
${PREFIX}_set_encrypt_key_alt:
.cfi_startproc
.seh_startproc
	_CET_ENDBR
#ifdef BORINGSSL_DISPATCH_TEST
	movb \$1,BORINGSSL_function_hit+3(%rip)
#endif
	sub	\$8,%rsp
.cfi_adjust_cfa_offset	8
.seh_stackalloc	8
.seh_endprologue
	vmovups	($inp),%xmm0		# pull first 128 bits of *userKey
	vxorps	%xmm4,%xmm4		# low dword of xmm4 is assumed 0
	lea	16($key),%rax		# %rax is used as modifiable copy of $key
	cmp	\$256,$bits
	je	.L14rounds_alt
	# 192-bit key support was removed.
	cmp	\$128,$bits
	jne	.Lbad_keybits_alt

	mov	\$9,$bits			# 10 rounds for 128-bit key
	vmovdqa	.Lkey_rotate(%rip),%xmm5
	mov	\$8,%r10d
	vmovdqa	.Lkey_rcon1(%rip),%xmm4
	vmovdqa	%xmm0,%xmm2
	vmovdqu	%xmm0,($key)
	jmp	.Loop_key128

.align	16
.Loop_key128:
	vpshufb		%xmm5,%xmm0
	vaesenclast	%xmm4,%xmm0
	vpslld		\$1,%xmm4
	lea		16(%rax),%rax

	vmovdqa		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm3,%xmm2

	vpxor		%xmm2,%xmm0
	vmovdqu		%xmm0,-16(%rax)
	vmovdqa		%xmm0,%xmm2

	dec	%r10d
	jnz	.Loop_key128

	vmovdqa		.Lkey_rcon1b(%rip),%xmm4

	vpshufb		%xmm5,%xmm0
	vaesenclast	%xmm4,%xmm0
	vpslld		\$1,%xmm4

	vmovdqa		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm3,%xmm2

	vpxor		%xmm2,%xmm0
	vmovdqu		%xmm0,(%rax)

	vmovdqa		%xmm0,%xmm2
	vpshufb		%xmm5,%xmm0
	vaesenclast	%xmm4,%xmm0

	vmovdqa		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm2,%xmm3
	vpslldq		\$4,%xmm2
	vpxor		%xmm3,%xmm2

	vpxor		%xmm2,%xmm0
	vmovdqu		%xmm0,16(%rax)

	mov	$bits,96(%rax)	# 240($key)
	xor	%eax,%eax
	jmp	.Lenc_key_ret_alt

	# 192-bit key support was removed.

.align	16
.L14rounds_alt:
	vmovups	16($inp),%xmm2			# remaining half of *userKey
	mov	\$13,$bits			# 14 rounds for 256
	lea	16(%rax),%rax
	vmovdqa	.Lkey_rotate(%rip),%xmm5
	vmovdqa	.Lkey_rcon1(%rip),%xmm4
	mov	\$7,%r10d
	vmovdqu	%xmm0,0($key)
	vmovdqa	%xmm2,%xmm1
	vmovdqu	%xmm2,16($key)
	jmp	.Loop_key256

.align	16
.Loop_key256:
	vpshufb		%xmm5,%xmm2
	vaesenclast	%xmm4,%xmm2

	vmovdqa		%xmm0,%xmm3
	vpslldq		\$4,%xmm0
	vpxor		%xmm0,%xmm3
	vpslldq		\$4,%xmm0
	vpxor		%xmm0,%xmm3
	vpslldq		\$4,%xmm0
	vpxor		%xmm3,%xmm0
	vpslld		\$1,%xmm4

	vpxor		%xmm2,%xmm0
	vmovdqu		%xmm0,(%rax)

	dec	%r10d
	jz	.Ldone_key256

	vpshufd		\$0xff,%xmm0,%xmm2
	vpxor		%xmm3,%xmm3
	vaesenclast	%xmm3,%xmm2

	vmovdqa		%xmm1,%xmm3
	vpslldq		\$4,%xmm1
	vpxor		%xmm1,%xmm3
	vpslldq		\$4,%xmm1
	vpxor		%xmm1,%xmm3
	vpslldq		\$4,%xmm1
	vpxor		%xmm3,%xmm1

	vpxor		%xmm1,%xmm2
	vmovdqu		%xmm2,16(%rax)
	lea		32(%rax),%rax
	vmovdqa		%xmm2,%xmm1

	jmp	.Loop_key256

.Ldone_key256:
	mov	$bits,16(%rax)	# 240($key)
	xor	%eax,%eax
	jmp	.Lenc_key_ret_alt

.align	16
.Lbad_keybits_alt:
	mov	\$-2,%rax
.Lenc_key_ret_alt:
	vpxor	%xmm0,%xmm0
	vpxor	%xmm1,%xmm1
	vpxor	%xmm2,%xmm2
	vpxor	%xmm3,%xmm3
	vpxor	%xmm4,%xmm4
	vpxor	%xmm5,%xmm5
	add	\$8,%rsp
.cfi_adjust_cfa_offset	-8
	ret
.cfi_endproc
.seh_endproc
.size	${PREFIX}_set_encrypt_key_alt,.-${PREFIX}_set_encrypt_key_alt
___
}

$code.=<<___;
.section .rodata
.align	64
.Lkey_rotate:
	.long	0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
.Lkey_rcon1:
	.long	1,1,1,1
.Lkey_rcon1b:
	.long	0x1b,0x1b,0x1b,0x1b

.asciz  "AES for Intel AES-NI, CRYPTOGAMS by <appro\@openssl.org>"
.align	64
.text
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT or die "error closing STDOUT: $!";
