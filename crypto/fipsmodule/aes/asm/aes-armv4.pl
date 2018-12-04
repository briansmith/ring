#! /usr/bin/env perl
# Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# AES for ARMv4

# January 2007.
#
# Code uses single 1K S-box and is >2 times faster than code generated
# by gcc-3.4.1. This is thanks to unique feature of ARMv4 ISA, which
# allows to merge logical or arithmetic operation with shift or rotate
# in one instruction and emit combined result every cycle. The module
# is endian-neutral. The performance is ~42 cycles/byte for 128-bit
# key [on single-issue Xscale PXA250 core].

# May 2007.
#
# AES_set_[en|de]crypt_key is added.

# July 2010.
#
# Rescheduling for dual-issue pipeline resulted in 12% improvement on
# Cortex A8 core and ~25 cycles per byte processed with 128-bit key.

# February 2011.
#
# Profiler-assisted and platform-specific optimization resulted in 16%
# improvement on Cortex A8 core and ~21.5 cycles per byte.

$flavour = shift;
if ($flavour=~/\w[\w\-]*\.\w+$/) { $output=$flavour; undef $flavour; }
else { while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {} }

if ($flavour && $flavour ne "void") {
    $0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
    ( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
    ( $xlate="${dir}../../../perlasm/arm-xlate.pl" and -f $xlate) or
    die "can't locate arm-xlate.pl";

    open STDOUT,"| \"$^X\" $xlate $flavour $output";
} else {
    open STDOUT,">$output";
}

$s0="r0";
$s1="r1";
$s2="r2";
$s3="r3";
$t1="r4";
$t2="r5";
$t3="r6";
$i1="r7";
$i2="r8";
$i3="r9";

$tbl="r10";
$key="r11";
$rounds="r12";

$code=<<___;
#ifndef __KERNEL__
# include <GFp/arm_arch.h>
#else
# define __ARM_ARCH__ __LINUX_ARM_ARCH__
#endif

@ Silence ARMv8 deprecated IT instruction warnings. This file is used by both
@ ARMv7 and ARMv8 processors and does not use ARMv8 instructions. (ARMv8 AES
@ instructions are in aesv8-armx.pl.)
.arch  armv7-a

.text
#if defined(__thumb2__) && !defined(__APPLE__)
.syntax	unified
.thumb
#else
.code	32
#undef __thumb2__
#endif

.type	AES_Te,%object
.align	5
AES_Te:
.word	0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d
.word	0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554
.word	0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d
.word	0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a
.word	0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87
.word	0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b
.word	0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea
.word	0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b
.word	0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a
.word	0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f
.word	0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108
.word	0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f
.word	0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e
.word	0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5
.word	0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d
.word	0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f
.word	0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e
.word	0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb
.word	0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce
.word	0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497
.word	0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c
.word	0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed
.word	0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b
.word	0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a
.word	0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16
.word	0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594
.word	0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81
.word	0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3
.word	0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a
.word	0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504
.word	0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163
.word	0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d
.word	0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f
.word	0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739
.word	0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47
.word	0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395
.word	0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f
.word	0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883
.word	0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c
.word	0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76
.word	0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e
.word	0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4
.word	0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6
.word	0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b
.word	0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7
.word	0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0
.word	0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25
.word	0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818
.word	0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72
.word	0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651
.word	0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21
.word	0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85
.word	0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa
.word	0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12
.word	0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0
.word	0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9
.word	0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133
.word	0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7
.word	0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920
.word	0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a
.word	0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17
.word	0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8
.word	0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11
.word	0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a
@ Te4[256]
.byte	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
.byte	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
.byte	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0
.byte	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
.byte	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc
.byte	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
.byte	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a
.byte	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
.byte	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0
.byte	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
.byte	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b
.byte	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
.byte	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85
.byte	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
.byte	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5
.byte	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
.byte	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17
.byte	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
.byte	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88
.byte	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
.byte	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c
.byte	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
.byte	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9
.byte	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
.byte	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6
.byte	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
.byte	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e
.byte	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
.byte	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94
.byte	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
.byte	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68
.byte	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
@ rcon[]
.word	0x01000000, 0x02000000, 0x04000000, 0x08000000
.word	0x10000000, 0x20000000, 0x40000000, 0x80000000
.word	0x1B000000, 0x36000000, 0, 0, 0, 0, 0, 0
.size	AES_Te,.-AES_Te

@ void GFp_aes_nohw_encrypt(const unsigned char *in, unsigned char *out,
@ 		                   const AES_KEY *key) {
.global GFp_aes_nohw_encrypt
.type   GFp_aes_nohw_encrypt,%function
.align	5
GFp_aes_nohw_encrypt:
#ifndef	__thumb2__
	sub	r3,pc,#8		@ GFp_aes_nohw_encrypt
#else
	adr	r3,.
#endif
	stmdb   sp!,{r1,r4-r12,lr}
#if defined(__thumb2__) || defined(__APPLE__)
	adr	$tbl,AES_Te
#else
	sub	$tbl,r3,#GFp_aes_nohw_encrypt-AES_Te	@ Te
#endif
	mov	$rounds,r0		@ inp
	mov	$key,r2
#if __ARM_ARCH__<7
	ldrb	$s0,[$rounds,#3]	@ load input data in endian-neutral
	ldrb	$t1,[$rounds,#2]	@ manner...
	ldrb	$t2,[$rounds,#1]
	ldrb	$t3,[$rounds,#0]
	orr	$s0,$s0,$t1,lsl#8
	ldrb	$s1,[$rounds,#7]
	orr	$s0,$s0,$t2,lsl#16
	ldrb	$t1,[$rounds,#6]
	orr	$s0,$s0,$t3,lsl#24
	ldrb	$t2,[$rounds,#5]
	ldrb	$t3,[$rounds,#4]
	orr	$s1,$s1,$t1,lsl#8
	ldrb	$s2,[$rounds,#11]
	orr	$s1,$s1,$t2,lsl#16
	ldrb	$t1,[$rounds,#10]
	orr	$s1,$s1,$t3,lsl#24
	ldrb	$t2,[$rounds,#9]
	ldrb	$t3,[$rounds,#8]
	orr	$s2,$s2,$t1,lsl#8
	ldrb	$s3,[$rounds,#15]
	orr	$s2,$s2,$t2,lsl#16
	ldrb	$t1,[$rounds,#14]
	orr	$s2,$s2,$t3,lsl#24
	ldrb	$t2,[$rounds,#13]
	ldrb	$t3,[$rounds,#12]
	orr	$s3,$s3,$t1,lsl#8
	orr	$s3,$s3,$t2,lsl#16
	orr	$s3,$s3,$t3,lsl#24
#else
	ldr	$s0,[$rounds,#0]
	ldr	$s1,[$rounds,#4]
	ldr	$s2,[$rounds,#8]
	ldr	$s3,[$rounds,#12]
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
#endif
	bl	_armv4_AES_encrypt

	ldr	$rounds,[sp],#4		@ pop out
#if __ARM_ARCH__>=7
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
	str	$s0,[$rounds,#0]
	str	$s1,[$rounds,#4]
	str	$s2,[$rounds,#8]
	str	$s3,[$rounds,#12]
#else
	mov	$t1,$s0,lsr#24		@ write output in endian-neutral
	mov	$t2,$s0,lsr#16		@ manner...
	mov	$t3,$s0,lsr#8
	strb	$t1,[$rounds,#0]
	strb	$t2,[$rounds,#1]
	mov	$t1,$s1,lsr#24
	strb	$t3,[$rounds,#2]
	mov	$t2,$s1,lsr#16
	strb	$s0,[$rounds,#3]
	mov	$t3,$s1,lsr#8
	strb	$t1,[$rounds,#4]
	strb	$t2,[$rounds,#5]
	mov	$t1,$s2,lsr#24
	strb	$t3,[$rounds,#6]
	mov	$t2,$s2,lsr#16
	strb	$s1,[$rounds,#7]
	mov	$t3,$s2,lsr#8
	strb	$t1,[$rounds,#8]
	strb	$t2,[$rounds,#9]
	mov	$t1,$s3,lsr#24
	strb	$t3,[$rounds,#10]
	mov	$t2,$s3,lsr#16
	strb	$s2,[$rounds,#11]
	mov	$t3,$s3,lsr#8
	strb	$t1,[$rounds,#12]
	strb	$t2,[$rounds,#13]
	strb	$t3,[$rounds,#14]
	strb	$s3,[$rounds,#15]
#endif
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r12,pc}
#else
	ldmia   sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
#endif
.size	GFp_aes_nohw_encrypt,.-GFp_aes_nohw_encrypt

.type   _armv4_AES_encrypt,%function
.align	2
_armv4_AES_encrypt:
	str	lr,[sp,#-4]!		@ push lr
	ldmia	$key!,{$t1-$i1}
	eor	$s0,$s0,$t1
	ldr	$rounds,[$key,#240-16]
	eor	$s1,$s1,$t2
	eor	$s2,$s2,$t3
	eor	$s3,$s3,$i1
	sub	$rounds,$rounds,#1
	mov	lr,#255

	and	$i1,lr,$s0
	and	$i2,lr,$s0,lsr#8
	and	$i3,lr,$s0,lsr#16
	mov	$s0,$s0,lsr#24
.Lenc_loop:
	ldr	$t1,[$tbl,$i1,lsl#2]	@ Te3[s0>>0]
	and	$i1,lr,$s1,lsr#16	@ i0
	ldr	$t2,[$tbl,$i2,lsl#2]	@ Te2[s0>>8]
	and	$i2,lr,$s1
	ldr	$t3,[$tbl,$i3,lsl#2]	@ Te1[s0>>16]
	and	$i3,lr,$s1,lsr#8
	ldr	$s0,[$tbl,$s0,lsl#2]	@ Te0[s0>>24]
	mov	$s1,$s1,lsr#24

	ldr	$i1,[$tbl,$i1,lsl#2]	@ Te1[s1>>16]
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Te3[s1>>0]
	ldr	$i3,[$tbl,$i3,lsl#2]	@ Te2[s1>>8]
	eor	$s0,$s0,$i1,ror#8
	ldr	$s1,[$tbl,$s1,lsl#2]	@ Te0[s1>>24]
	and	$i1,lr,$s2,lsr#8	@ i0
	eor	$t2,$t2,$i2,ror#8
	and	$i2,lr,$s2,lsr#16	@ i1
	eor	$t3,$t3,$i3,ror#8
	and	$i3,lr,$s2
	ldr	$i1,[$tbl,$i1,lsl#2]	@ Te2[s2>>8]
	eor	$s1,$s1,$t1,ror#24
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Te1[s2>>16]
	mov	$s2,$s2,lsr#24

	ldr	$i3,[$tbl,$i3,lsl#2]	@ Te3[s2>>0]
	eor	$s0,$s0,$i1,ror#16
	ldr	$s2,[$tbl,$s2,lsl#2]	@ Te0[s2>>24]
	and	$i1,lr,$s3		@ i0
	eor	$s1,$s1,$i2,ror#8
	and	$i2,lr,$s3,lsr#8	@ i1
	eor	$t3,$t3,$i3,ror#16
	and	$i3,lr,$s3,lsr#16	@ i2
	ldr	$i1,[$tbl,$i1,lsl#2]	@ Te3[s3>>0]
	eor	$s2,$s2,$t2,ror#16
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Te2[s3>>8]
	mov	$s3,$s3,lsr#24

	ldr	$i3,[$tbl,$i3,lsl#2]	@ Te1[s3>>16]
	eor	$s0,$s0,$i1,ror#24
	ldr	$i1,[$key],#16
	eor	$s1,$s1,$i2,ror#16
	ldr	$s3,[$tbl,$s3,lsl#2]	@ Te0[s3>>24]
	eor	$s2,$s2,$i3,ror#8
	ldr	$t1,[$key,#-12]
	eor	$s3,$s3,$t3,ror#8

	ldr	$t2,[$key,#-8]
	eor	$s0,$s0,$i1
	ldr	$t3,[$key,#-4]
	and	$i1,lr,$s0
	eor	$s1,$s1,$t1
	and	$i2,lr,$s0,lsr#8
	eor	$s2,$s2,$t2
	and	$i3,lr,$s0,lsr#16
	eor	$s3,$s3,$t3
	mov	$s0,$s0,lsr#24

	subs	$rounds,$rounds,#1
	bne	.Lenc_loop

	add	$tbl,$tbl,#2

	ldrb	$t1,[$tbl,$i1,lsl#2]	@ Te4[s0>>0]
	and	$i1,lr,$s1,lsr#16	@ i0
	ldrb	$t2,[$tbl,$i2,lsl#2]	@ Te4[s0>>8]
	and	$i2,lr,$s1
	ldrb	$t3,[$tbl,$i3,lsl#2]	@ Te4[s0>>16]
	and	$i3,lr,$s1,lsr#8
	ldrb	$s0,[$tbl,$s0,lsl#2]	@ Te4[s0>>24]
	mov	$s1,$s1,lsr#24

	ldrb	$i1,[$tbl,$i1,lsl#2]	@ Te4[s1>>16]
	ldrb	$i2,[$tbl,$i2,lsl#2]	@ Te4[s1>>0]
	ldrb	$i3,[$tbl,$i3,lsl#2]	@ Te4[s1>>8]
	eor	$s0,$i1,$s0,lsl#8
	ldrb	$s1,[$tbl,$s1,lsl#2]	@ Te4[s1>>24]
	and	$i1,lr,$s2,lsr#8	@ i0
	eor	$t2,$i2,$t2,lsl#8
	and	$i2,lr,$s2,lsr#16	@ i1
	eor	$t3,$i3,$t3,lsl#8
	and	$i3,lr,$s2
	ldrb	$i1,[$tbl,$i1,lsl#2]	@ Te4[s2>>8]
	eor	$s1,$t1,$s1,lsl#24
	ldrb	$i2,[$tbl,$i2,lsl#2]	@ Te4[s2>>16]
	mov	$s2,$s2,lsr#24

	ldrb	$i3,[$tbl,$i3,lsl#2]	@ Te4[s2>>0]
	eor	$s0,$i1,$s0,lsl#8
	ldrb	$s2,[$tbl,$s2,lsl#2]	@ Te4[s2>>24]
	and	$i1,lr,$s3		@ i0
	eor	$s1,$s1,$i2,lsl#16
	and	$i2,lr,$s3,lsr#8	@ i1
	eor	$t3,$i3,$t3,lsl#8
	and	$i3,lr,$s3,lsr#16	@ i2
	ldrb	$i1,[$tbl,$i1,lsl#2]	@ Te4[s3>>0]
	eor	$s2,$t2,$s2,lsl#24
	ldrb	$i2,[$tbl,$i2,lsl#2]	@ Te4[s3>>8]
	mov	$s3,$s3,lsr#24

	ldrb	$i3,[$tbl,$i3,lsl#2]	@ Te4[s3>>16]
	eor	$s0,$i1,$s0,lsl#8
	ldr	$i1,[$key,#0]
	ldrb	$s3,[$tbl,$s3,lsl#2]	@ Te4[s3>>24]
	eor	$s1,$s1,$i2,lsl#8
	ldr	$t1,[$key,#4]
	eor	$s2,$s2,$i3,lsl#16
	ldr	$t2,[$key,#8]
	eor	$s3,$t3,$s3,lsl#24
	ldr	$t3,[$key,#12]

	eor	$s0,$s0,$i1
	eor	$s1,$s1,$t1
	eor	$s2,$s2,$t2
	eor	$s3,$s3,$t3

	sub	$tbl,$tbl,#2
	ldr	pc,[sp],#4		@ pop and return
.size	_armv4_AES_encrypt,.-_armv4_AES_encrypt

.global GFp_aes_nohw_set_encrypt_key
.type   GFp_aes_nohw_set_encrypt_key,%function
.align	5
GFp_aes_nohw_set_encrypt_key:
_armv4_AES_set_encrypt_key:
#ifndef	__thumb2__
	sub	r3,pc,#8		@ GFp_aes_nohw_set_encrypt_key
#else
	adr	r3,.
#endif
	teq	r0,#0
#ifdef	__thumb2__
	itt	eq			@ Thumb2 thing, sanity check in ARM
#endif
	moveq	r0,#-1
	beq	.Labrt
	teq	r2,#0
#ifdef	__thumb2__
	itt	eq			@ Thumb2 thing, sanity check in ARM
#endif
	moveq	r0,#-1
	beq	.Labrt

	teq	r1,#128
	beq	.Lok
	teq	r1,#256
#ifdef	__thumb2__
	itt	ne			@ Thumb2 thing, sanity check in ARM
#endif
	movne	r0,#-1
	bne	.Labrt

.Lok:	stmdb   sp!,{r4-r12,lr}
	mov	$rounds,r0		@ inp
	mov	lr,r1			@ bits
	mov	$key,r2			@ key

#if defined(__thumb2__) || defined(__APPLE__)
	adr	$tbl,AES_Te+1024				@ Te4
#else
	sub	$tbl,r3,#_armv4_AES_set_encrypt_key-AES_Te-1024	@ Te4
#endif

#if __ARM_ARCH__<7
	ldrb	$s0,[$rounds,#3]	@ load input data in endian-neutral
	ldrb	$t1,[$rounds,#2]	@ manner...
	ldrb	$t2,[$rounds,#1]
	ldrb	$t3,[$rounds,#0]
	orr	$s0,$s0,$t1,lsl#8
	ldrb	$s1,[$rounds,#7]
	orr	$s0,$s0,$t2,lsl#16
	ldrb	$t1,[$rounds,#6]
	orr	$s0,$s0,$t3,lsl#24
	ldrb	$t2,[$rounds,#5]
	ldrb	$t3,[$rounds,#4]
	orr	$s1,$s1,$t1,lsl#8
	ldrb	$s2,[$rounds,#11]
	orr	$s1,$s1,$t2,lsl#16
	ldrb	$t1,[$rounds,#10]
	orr	$s1,$s1,$t3,lsl#24
	ldrb	$t2,[$rounds,#9]
	ldrb	$t3,[$rounds,#8]
	orr	$s2,$s2,$t1,lsl#8
	ldrb	$s3,[$rounds,#15]
	orr	$s2,$s2,$t2,lsl#16
	ldrb	$t1,[$rounds,#14]
	orr	$s2,$s2,$t3,lsl#24
	ldrb	$t2,[$rounds,#13]
	ldrb	$t3,[$rounds,#12]
	orr	$s3,$s3,$t1,lsl#8
	str	$s0,[$key],#16
	orr	$s3,$s3,$t2,lsl#16
	str	$s1,[$key,#-12]
	orr	$s3,$s3,$t3,lsl#24
	str	$s2,[$key,#-8]
	str	$s3,[$key,#-4]
#else
	ldr	$s0,[$rounds,#0]
	ldr	$s1,[$rounds,#4]
	ldr	$s2,[$rounds,#8]
	ldr	$s3,[$rounds,#12]
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
	str	$s0,[$key],#16
	str	$s1,[$key,#-12]
	str	$s2,[$key,#-8]
	str	$s3,[$key,#-4]
#endif

	teq	lr,#128
	bne	.Lnot128
	mov	$rounds,#10
	str	$rounds,[$key,#240-16]
	add	$t3,$tbl,#256			@ rcon
	mov	lr,#255

.L128_loop:
	and	$t2,lr,$s3,lsr#24
	and	$i1,lr,$s3,lsr#16
	ldrb	$t2,[$tbl,$t2]
	and	$i2,lr,$s3,lsr#8
	ldrb	$i1,[$tbl,$i1]
	and	$i3,lr,$s3
	ldrb	$i2,[$tbl,$i2]
	orr	$t2,$t2,$i1,lsl#24
	ldrb	$i3,[$tbl,$i3]
	orr	$t2,$t2,$i2,lsl#16
	ldr	$t1,[$t3],#4			@ rcon[i++]
	orr	$t2,$t2,$i3,lsl#8
	eor	$t2,$t2,$t1
	eor	$s0,$s0,$t2			@ rk[4]=rk[0]^...
	eor	$s1,$s1,$s0			@ rk[5]=rk[1]^rk[4]
	str	$s0,[$key],#16
	eor	$s2,$s2,$s1			@ rk[6]=rk[2]^rk[5]
	str	$s1,[$key,#-12]
	eor	$s3,$s3,$s2			@ rk[7]=rk[3]^rk[6]
	str	$s2,[$key,#-8]
	subs	$rounds,$rounds,#1
	str	$s3,[$key,#-4]
	bne	.L128_loop
	sub	r2,$key,#176
	b	.Ldone

.Lnot128:
#if __ARM_ARCH__<7
	ldrb	$i2,[$rounds,#19]
	ldrb	$t1,[$rounds,#18]
	ldrb	$t2,[$rounds,#17]
	ldrb	$t3,[$rounds,#16]
	orr	$i2,$i2,$t1,lsl#8
	ldrb	$i3,[$rounds,#23]
	orr	$i2,$i2,$t2,lsl#16
	ldrb	$t1,[$rounds,#22]
	orr	$i2,$i2,$t3,lsl#24
	ldrb	$t2,[$rounds,#21]
	ldrb	$t3,[$rounds,#20]
	orr	$i3,$i3,$t1,lsl#8
	orr	$i3,$i3,$t2,lsl#16
	str	$i2,[$key],#8
	orr	$i3,$i3,$t3,lsl#24
	str	$i3,[$key,#-4]
#else
	ldr	$i2,[$rounds,#16]
	ldr	$i3,[$rounds,#20]
#ifdef __ARMEL__
	rev	$i2,$i2
	rev	$i3,$i3
#endif
	str	$i2,[$key],#8
	str	$i3,[$key,#-4]
#endif

#if __ARM_ARCH__<7
	ldrb	$i2,[$rounds,#27]
	ldrb	$t1,[$rounds,#26]
	ldrb	$t2,[$rounds,#25]
	ldrb	$t3,[$rounds,#24]
	orr	$i2,$i2,$t1,lsl#8
	ldrb	$i3,[$rounds,#31]
	orr	$i2,$i2,$t2,lsl#16
	ldrb	$t1,[$rounds,#30]
	orr	$i2,$i2,$t3,lsl#24
	ldrb	$t2,[$rounds,#29]
	ldrb	$t3,[$rounds,#28]
	orr	$i3,$i3,$t1,lsl#8
	orr	$i3,$i3,$t2,lsl#16
	str	$i2,[$key],#8
	orr	$i3,$i3,$t3,lsl#24
	str	$i3,[$key,#-4]
#else
	ldr	$i2,[$rounds,#24]
	ldr	$i3,[$rounds,#28]
#ifdef __ARMEL__
	rev	$i2,$i2
	rev	$i3,$i3
#endif
	str	$i2,[$key],#8
	str	$i3,[$key,#-4]
#endif

	mov	$rounds,#14
	str	$rounds,[$key,#240-32]
	add	$t3,$tbl,#256			@ rcon
	mov	lr,#255
	mov	$rounds,#7

.L256_loop:
	and	$t2,lr,$i3,lsr#24
	and	$i1,lr,$i3,lsr#16
	ldrb	$t2,[$tbl,$t2]
	and	$i2,lr,$i3,lsr#8
	ldrb	$i1,[$tbl,$i1]
	and	$i3,lr,$i3
	ldrb	$i2,[$tbl,$i2]
	orr	$t2,$t2,$i1,lsl#24
	ldrb	$i3,[$tbl,$i3]
	orr	$t2,$t2,$i2,lsl#16
	ldr	$t1,[$t3],#4			@ rcon[i++]
	orr	$t2,$t2,$i3,lsl#8
	eor	$i3,$t2,$t1
	eor	$s0,$s0,$i3			@ rk[8]=rk[0]^...
	eor	$s1,$s1,$s0			@ rk[9]=rk[1]^rk[8]
	str	$s0,[$key],#32
	eor	$s2,$s2,$s1			@ rk[10]=rk[2]^rk[9]
	str	$s1,[$key,#-28]
	eor	$s3,$s3,$s2			@ rk[11]=rk[3]^rk[10]
	str	$s2,[$key,#-24]
	subs	$rounds,$rounds,#1
	str	$s3,[$key,#-20]
#ifdef	__thumb2__
	itt	eq				@ Thumb2 thing, sanity check in ARM
#endif
	subeq	r2,$key,#256
	beq	.Ldone

	and	$t2,lr,$s3
	and	$i1,lr,$s3,lsr#8
	ldrb	$t2,[$tbl,$t2]
	and	$i2,lr,$s3,lsr#16
	ldrb	$i1,[$tbl,$i1]
	and	$i3,lr,$s3,lsr#24
	ldrb	$i2,[$tbl,$i2]
	orr	$t2,$t2,$i1,lsl#8
	ldrb	$i3,[$tbl,$i3]
	orr	$t2,$t2,$i2,lsl#16
	ldr	$t1,[$key,#-48]
	orr	$t2,$t2,$i3,lsl#24

	ldr	$i1,[$key,#-44]
	ldr	$i2,[$key,#-40]
	eor	$t1,$t1,$t2			@ rk[12]=rk[4]^...
	ldr	$i3,[$key,#-36]
	eor	$i1,$i1,$t1			@ rk[13]=rk[5]^rk[12]
	str	$t1,[$key,#-16]
	eor	$i2,$i2,$i1			@ rk[14]=rk[6]^rk[13]
	str	$i1,[$key,#-12]
	eor	$i3,$i3,$i2			@ rk[15]=rk[7]^rk[14]
	str	$i2,[$key,#-8]
	str	$i3,[$key,#-4]
	b	.L256_loop

.align	2
.Ldone:	mov	r0,#0
	ldmia   sp!,{r4-r12,lr}
.Labrt:
#if __ARM_ARCH__>=5
	ret				@ bx lr
#else
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
#endif
.size	GFp_aes_nohw_set_encrypt_key,.-GFp_aes_nohw_set_encrypt_key

.asciz	"AES for ARMv4, CRYPTOGAMS by <appro\@openssl.org>"
.align	2
___

$code =~ s/\bbx\s+lr\b/.word\t0xe12fff1e/gm;	# make it possible to compile with -march=armv4
$code =~ s/\bret\b/bx\tlr/gm;

open SELF,$0;
while(<SELF>) {
	next if (/^#!/);
	last if (!s/^#/@/ and !/^$/);
	print;
}
close SELF;

print $code;
close STDOUT;	# enforce flush
