// Copyright (c) 2018, Google Inc.
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
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// This file is produced by compiling hrss.c with Clang and -mfpu=neon, and
// then trimming the output to just include the vectorised functions.

#if !defined(OPENSSL_NO_ASM) && !defined(__ARM_NEON__)

	.text
	.syntax unified
	.eabi_attribute	67, "2.09"	@ Tag_conformance
	.eabi_attribute	6, 10	@ Tag_CPU_arch
	.eabi_attribute	7, 65	@ Tag_CPU_arch_profile
	.eabi_attribute	8, 1	@ Tag_ARM_ISA_use
	.eabi_attribute	9, 2	@ Tag_THUMB_ISA_use
	.fpu	neon
	.eabi_attribute	34, 1	@ Tag_CPU_unaligned_access
	.eabi_attribute	15, 1	@ Tag_ABI_PCS_RW_data
	.eabi_attribute	16, 1	@ Tag_ABI_PCS_RO_data
	.eabi_attribute	17, 2	@ Tag_ABI_PCS_GOT_use
	.eabi_attribute	20, 1	@ Tag_ABI_FP_denormal
	.eabi_attribute	21, 1	@ Tag_ABI_FP_exceptions
	.eabi_attribute	23, 3	@ Tag_ABI_FP_number_model
	.eabi_attribute	24, 1	@ Tag_ABI_align_needed
	.eabi_attribute	25, 1	@ Tag_ABI_align_preserved
	.eabi_attribute	38, 1	@ Tag_ABI_FP_16bit_format
	.eabi_attribute	18, 4	@ Tag_ABI_PCS_wchar_t
	.eabi_attribute	26, 2	@ Tag_ABI_enum_size
	.eabi_attribute	14, 0	@ Tag_ABI_PCS_R9_use
	.file	"hrss.c"

	.section	.text.poly3_invert_vec,"ax",%progbits
	.hidden	poly3_invert_vec        @ -- Begin function poly3_invert_vec
	.globl	poly3_invert_vec
	.p2align	4
	.type	poly3_invert_vec,%function
	.code	16                      @ @poly3_invert_vec
	.thumb_func
poly3_invert_vec:
.Lfunc_begin0:
	.file	1 "../crypto/hrss/hrss.c"
	.loc	1 718 0                 @ ../crypto/hrss/hrss.c:718:0
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.setfp	r7, sp, #12
	add	r7, sp, #12
	.cfi_def_cfa r7, 8
	.save	{r8, r9, r10}
	push.w	{r8, r9, r10}
	.cfi_offset r10, -24
	.cfi_offset r9, -28
	.cfi_offset r8, -32
	.vsave	{d8, d9, d10, d11, d12, d13, d14, d15}
	vpush	{d8, d9, d10, d11, d12, d13, d14, d15}
	.cfi_offset d15, -40
	.cfi_offset d14, -48
	.cfi_offset d13, -56
	.cfi_offset d12, -64
	.cfi_offset d11, -72
	.cfi_offset d10, -80
	.cfi_offset d9, -88
	.cfi_offset d8, -96
	.pad	#944
	sub.w	sp, sp, #944
	mov	r4, sp
	bfc	r4, #0, #4
	mov	sp, r4
	mov	r10, r0
.Ltmp0:
	.loc	1 735 3 prologue_end    @ ../crypto/hrss/hrss.c:735:3
	movs	r0, #104
	.loc	1 733 3                 @ ../crypto/hrss/hrss.c:733:3
	mov	r2, r1
	add.w	lr, sp, #704
	vld1.16	{d4, d5}, [r2], r0
	adr	r0, .LCPI0_2
	vmov.i8	q14, #0xff
	mov.w	r5, #700
	vld1.64	{d16, d17}, [r0:128]
	adr	r0, .LCPI0_3
	vmov.i32	q1, #0x0
	mvn	r12, #-2147483648
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	.loc	1 735 3                 @ ../crypto/hrss/hrss.c:735:3
	add.w	lr, sp, #672
	vmov.i32	q11, #0x0
	mov.w	r6, #700
	vld1.64	{d16, d17}, [r0:128]
	add.w	r0, r1, #152
	vmov.i32	q12, #0x0
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #384
	vld1.32	{d16, d17}, [r2]
	.loc	1 733 3                 @ ../crypto/hrss/hrss.c:733:3
	add.w	r2, r1, #64
	.loc	1 735 3                 @ ../crypto/hrss/hrss.c:735:3
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #640
	vld1.32	{d16, d17}, [r0]
	add.w	r0, r1, #136
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #496
	vld1.32	{d16, d17}, [r0]
	add.w	r0, r1, #120
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #432
	vld1.32	{d16, d17}, [r0]
	add.w	r0, r1, #88
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	vmov.i32	d17, #0x0
	.loc	1 733 3                 @ ../crypto/hrss/hrss.c:733:3
	add.w	lr, sp, #544
	vld1.32	{d20, d21}, [r2]
	add.w	r2, r1, #32
	.loc	1 735 3                 @ ../crypto/hrss/hrss.c:735:3
	vld1.32	{d30, d31}, [r0]
	.loc	1 733 3                 @ ../crypto/hrss/hrss.c:733:3
	add.w	r0, r1, #16
	vldr	d18, [r1, #80]
	.loc	1 735 3                 @ ../crypto/hrss/hrss.c:735:3
	vldr	d16, [r1, #168]
	.loc	1 733 3                 @ ../crypto/hrss/hrss.c:733:3
	adds	r1, #48
	vst1.64	{d20, d21}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #416
	vorr	d19, d17, d17
	vld1.32	{d20, d21}, [r1]
	movs	r1, #0
	vst1.64	{d20, d21}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #400
	vld1.32	{d20, d21}, [r2]
	movw	r2, #1399
	vst1.64	{d20, d21}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #352
	vld1.32	{d20, d21}, [r0]
	add	r0, sp, #880
	vst1.64	{d20, d21}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #656
	vmov.i8	q10, #0xff
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	vmov.i16	q8, #0xf
	add.w	lr, sp, #624
	vneg.s16	q8, q8
	vst1.64	{d18, d19}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #608
	vmov.i8	q9, #0xff
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	vmov.i32	q8, #0x0
	mov.w	lr, #0
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vmov.i32	q8, #0x0
	add	r0, sp, #896
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #592
	vmov.i8	q8, #0xff
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i8	q9, #0xff
	add	r0, sp, #576
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i8	q9, #0xff
	add	r0, sp, #560
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #528
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #512
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #480
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #464
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #448
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #208
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #224
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #320
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #288
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #256
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #368
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #336
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #304
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #272
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #240
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #800
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #816
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #832
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #848
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #864
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #688
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #720
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #736
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #752
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	add	r0, sp, #784
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmov.i32	q9, #0x0
	.loc	1 747 3                 @ ../crypto/hrss/hrss.c:747:3
	add	r0, sp, #768
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	b	.LBB0_3
	.p2align	4
@ %bb.1:
	.loc	1 0 3 is_stmt 0         @ ../crypto/hrss/hrss.c:0:3
.LCPI0_2:
	.short	1                       @ 0x1
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.p2align	4
@ %bb.2:
.LCPI0_3:
	.short	65535                   @ 0xffff
	.short	65535                   @ 0xffff
	.short	65535                   @ 0xffff
	.short	8191                    @ 0x1fff
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.short	0                       @ 0x0
	.p2align	1
.LBB0_3:                                @ =>This Inner Loop Header: Depth=1
	.loc	1 749 32 is_stmt 1      @ ../crypto/hrss/hrss.c:749:32
	add	r0, sp, #96
	vand	q9, q1, q15
	.loc	1 751 32                @ ../crypto/hrss/hrss.c:751:32
	vand	q13, q8, q15
.Ltmp1:
	.file	2 "../crypto/hrss/../internal.h"
	.loc	2 270 42                @ ../crypto/hrss/../internal.h:270:42
	subs	r4, r5, r6
.Ltmp2:
	.loc	1 749 32                @ ../crypto/hrss/hrss.c:749:32
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #128
	.loc	1 749 52 is_stmt 0      @ ../crypto/hrss/hrss.c:749:52
	vand	q11, q8, q2
.Ltmp3:
	.loc	2 270 35 is_stmt 1      @ ../crypto/hrss/../internal.h:270:35
	eor.w	r3, r5, r6
.Ltmp4:
	.loc	1 749 32                @ ../crypto/hrss/hrss.c:749:32
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 751 52                @ ../crypto/hrss/hrss.c:751:52
	vand	q12, q1, q2
	.loc	1 749 42                @ ../crypto/hrss/hrss.c:749:42
	veor	q9, q11, q9
.Ltmp5:
	.loc	2 270 45                @ ../crypto/hrss/../internal.h:270:45
	eors	r4, r5
.Ltmp6:
	.loc	1 751 42                @ ../crypto/hrss/hrss.c:751:42
	veor	q11, q13, q12
.Ltmp7:
	.loc	2 270 38                @ ../crypto/hrss/../internal.h:270:38
	orrs	r4, r3
.Ltmp8:
	.loc	1 749 21                @ ../crypto/hrss/hrss.c:749:21
	vand	q12, q14, q9
.Ltmp9:
	.loc	2 270 31                @ ../crypto/hrss/../internal.h:270:31
	eors	r4, r5
.Ltmp10:
	.loc	1 751 21                @ ../crypto/hrss/hrss.c:751:21
	vand	q9, q14, q11
	.loc	1 749 32                @ ../crypto/hrss/hrss.c:749:32
	add	r0, sp, #912
.Ltmp11:
	.loc	2 234 13                @ ../crypto/hrss/../internal.h:234:13
	asrs	r4, r4, #31
.Ltmp12:
	.loc	1 747 26                @ ../crypto/hrss/hrss.c:747:26
	subs	r2, #1
.Ltmp13:
	.loc	1 185 7                 @ ../crypto/hrss/hrss.c:185:7
	vorr	q11, q9, q12
.Ltmp14:
	.loc	1 153 50                @ ../crypto/hrss/hrss.c:153:50
	vmov.16	d26[0], r4
.Ltmp15:
	.loc	1 185 7                 @ ../crypto/hrss/hrss.c:185:7
	vshl.i16	q9, q9, #15
.Ltmp16:
	.loc	1 749 32                @ ../crypto/hrss/hrss.c:749:32
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp17:
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	add	r0, sp, #192
.Ltmp18:
	.loc	1 185 7                 @ ../crypto/hrss/hrss.c:185:7
	vshl.i16	q11, q11, #15
.Ltmp19:
	.loc	1 753 14                @ ../crypto/hrss/hrss.c:753:14
	vshr.s16	q11, q11, #15
	.loc	1 753 21 is_stmt 0      @ ../crypto/hrss/hrss.c:753:21
	vand	q11, q13, q11
.Ltmp20:
	.loc	1 689 40 is_stmt 1      @ ../crypto/hrss/hrss.c:689:40
	veor	q13, q8, q15
.Ltmp21:
	.loc	1 753 21                @ ../crypto/hrss/hrss.c:753:21
	vdup.16	q0, d22[0]
.Ltmp22:
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q11, q1, q2
	.loc	1 689 30                @ ../crypto/hrss/hrss.c:689:30
	vand	q13, q0, q13
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q14, q0, q11
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q8, q13, q8
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q1, q14, q1
.Ltmp23:
	.loc	1 185 7                 @ ../crypto/hrss/hrss.c:185:7
	vshl.i16	q11, q12, #15
.Ltmp24:
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp25:
	.loc	1 185 7                 @ ../crypto/hrss/hrss.c:185:7
	add	r0, sp, #160
	vst1.64	{d2, d3}, [r0:128]      @ 16-byte Spill
	add	r0, sp, #608
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp26:
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	add	r0, sp, #144
.Ltmp27:
	.loc	1 185 7                 @ ../crypto/hrss/hrss.c:185:7
	vshl.s16	q9, q9, q3
.Ltmp28:
	.loc	1 185 7 is_stmt 0       @ ../crypto/hrss/hrss.c:185:7
	vshl.s16	q11, q11, q3
.Ltmp29:
	.loc	1 186 10 is_stmt 1      @ ../crypto/hrss/hrss.c:186:10
	vdup.16	q9, d18[0]
.Ltmp30:
	.loc	1 186 10 is_stmt 0      @ ../crypto/hrss/hrss.c:186:10
	vdup.16	q3, d22[0]
.Ltmp31:
	.loc	1 701 44 is_stmt 1      @ ../crypto/hrss/hrss.c:701:44
	vand	q12, q8, q9
	.loc	1 701 32 is_stmt 0      @ ../crypto/hrss/hrss.c:701:32
	vand	q11, q1, q3
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q5, q12, q11
	.loc	1 702 33 is_stmt 1      @ ../crypto/hrss/hrss.c:702:33
	vand	q12, q1, q9
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q1, q8, q3
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q4, q1, q12
.Ltmp32:
	.loc	1 686 12 is_stmt 1      @ ../crypto/hrss/hrss.c:686:12
	veor	q1, q14, q2
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q14, q13, q15
.Ltmp33:
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q2, q5, q1
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q8, q14, q1
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q13, q4, q8
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	.loc	1 706 34                @ ../crypto/hrss/hrss.c:706:34
	vorr	q8, q5, q4
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	add	r0, sp, #80
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q13, q13, q2
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q2, q14, q8
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #384
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q6, q13, q2
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
.Ltmp34:
	.loc	1 689 30 is_stmt 1      @ ../crypto/hrss/hrss.c:689:30
	add	r0, sp, #928
	.loc	1 689 40 is_stmt 0      @ ../crypto/hrss/hrss.c:689:40
	veor	q13, q10, q12
	.loc	1 689 30                @ ../crypto/hrss/hrss.c:689:30
	vst1.64	{d0, d1}, [r0:128]      @ 16-byte Spill
	.loc	1 685 40 is_stmt 1      @ ../crypto/hrss/hrss.c:685:40
	add	r0, sp, #176
	.loc	1 689 30                @ ../crypto/hrss/hrss.c:689:30
	vand	q13, q0, q13
.Ltmp35:
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q14, q4, q14
.Ltmp36:
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q10, q13, q10
.Ltmp37:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q15, q10, q9
.Ltmp38:
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #528
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp39:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	add	r0, sp, #16
.Ltmp40:
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q2, q8, q11
.Ltmp41:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #528
.Ltmp42:
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q2, q0, q2
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q8, q2, q8
.Ltmp43:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q7, q8, q3
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp44:
	.loc	1 223 33                @ ../crypto/hrss/hrss.c:223:33
	add	r0, sp, #32
.Ltmp45:
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q15, q15, q7
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q7, q8, q9
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q8, q10, q3
.Ltmp46:
	.loc	1 690 12 is_stmt 1      @ ../crypto/hrss/hrss.c:690:12
	veor	q10, q13, q12
.Ltmp47:
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q9, q8, q7
.Ltmp48:
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q7, q2, q11
.Ltmp49:
	.loc	1 706 34                @ ../crypto/hrss/hrss.c:706:34
	vorr	q12, q15, q9
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q0, q10, q7
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q2, q15, q7
	.loc	1 708 41 is_stmt 0      @ ../crypto/hrss/hrss.c:708:41
	vbic	q13, q9, q0
.Ltmp50:
	.loc	1 224 12 is_stmt 1      @ ../crypto/hrss/hrss.c:224:12
	vshr.u16	q11, q6, #1
.Ltmp51:
	.loc	1 708 35                @ ../crypto/hrss/hrss.c:708:35
	veor	q13, q13, q2
	.loc	1 708 60 is_stmt 0      @ ../crypto/hrss/hrss.c:708:60
	vbic	q2, q10, q12
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q8, q13, q2
	vmov.i32	q2, #0x0
.Ltmp52:
	.loc	1 223 33 is_stmt 1      @ ../crypto/hrss/hrss.c:223:33
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q8, #15
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	add	r0, sp, #384
	.loc	1 227 15                @ ../crypto/hrss/hrss.c:227:15
	vext.16	q13, q2, q8, #1
	.loc	1 225 12                @ ../crypto/hrss/hrss.c:225:12
	vorr	q11, q13, q11
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	.loc	1 223 33                @ ../crypto/hrss/hrss.c:223:33
	vshl.i16	q13, q6, #15
.Ltmp53:
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #80
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	.loc	1 707 41 is_stmt 0      @ ../crypto/hrss/hrss.c:707:41
	add	r0, sp, #144
.Ltmp54:
	.loc	1 225 15 is_stmt 1      @ ../crypto/hrss/hrss.c:225:15
	vext.16	q13, q13, q2, #1
	.loc	1 226 12                @ ../crypto/hrss/hrss.c:226:12
	vorr	q6, q11, q13
.Ltmp55:
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q11, q1, q8
	.loc	1 707 41 is_stmt 0      @ ../crypto/hrss/hrss.c:707:41
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	vbic	q13, q5, q8
.Ltmp56:
	.loc	1 218 12 is_stmt 1      @ ../crypto/hrss/hrss.c:218:12
	add	r0, sp, #352
.Ltmp57:
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q8, q9, q10
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q13, q13, q14
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q11, q13, q11
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q13, q7, q12
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q12, q15, q0
	.loc	1 707 35                @ ../crypto/hrss/hrss.c:707:35
	veor	q8, q12, q8
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q1, q8, q13
.Ltmp58:
	.loc	1 218 12 is_stmt 1      @ ../crypto/hrss/hrss.c:218:12
	vshr.u16	q8, q11, #1
	.loc	1 217 33                @ ../crypto/hrss/hrss.c:217:33
	vshl.i16	q9, q1, #15
	.loc	1 218 12                @ ../crypto/hrss/hrss.c:218:12
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #80
	.loc	1 221 15                @ ../crypto/hrss/hrss.c:221:15
	vext.16	q9, q2, q9, #1
	.loc	1 219 12                @ ../crypto/hrss/hrss.c:219:12
	vorr	q8, q9, q8
	.loc	1 217 33                @ ../crypto/hrss/hrss.c:217:33
	vshl.i16	q9, q11, #15
	.loc	1 219 15                @ ../crypto/hrss/hrss.c:219:15
	vext.16	q9, q9, q2, #1
	.loc	1 220 12                @ ../crypto/hrss/hrss.c:220:12
	vorr	q12, q8, q9
.Ltmp59:
	.loc	1 772 56                @ ../crypto/hrss/hrss.c:772:56
	vorr	q8, q12, q6
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #112
	vst1.64	{d12, d13}, [r0:128]    @ 16-byte Spill
.Ltmp60:
	.loc	1 185 7                 @ ../crypto/hrss/hrss.c:185:7
	add	r0, sp, #608
	vshl.i16	q8, q8, #15
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #144
	vshl.s16	q8, q8, q9
	.loc	1 186 10                @ ../crypto/hrss/hrss.c:186:10
	vdup.16	q11, d16[0]
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #896
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp61:
	.loc	1 777 40                @ ../crypto/hrss/hrss.c:777:40
	add	r0, sp, #912
	.loc	1 779 65                @ ../crypto/hrss/hrss.c:779:65
	veor	q8, q6, q10
	.loc	1 777 40                @ ../crypto/hrss/hrss.c:777:40
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #896
	vand	q9, q11, q9
	.loc	1 779 55                @ ../crypto/hrss/hrss.c:779:55
	vand	q8, q9, q8
	.loc	1 780 9                 @ ../crypto/hrss/hrss.c:780:9
	veor	q10, q8, q10
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #880
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #880
	.loc	1 777 65                @ ../crypto/hrss/hrss.c:777:65
	veor	q8, q12, q10
	.loc	1 777 55 is_stmt 0      @ ../crypto/hrss/hrss.c:777:55
	vand	q8, q9, q8
	.loc	1 778 9 is_stmt 1       @ ../crypto/hrss/hrss.c:778:9
	veor	q10, q8, q10
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #672
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #656
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #928
.Ltmp62:
	.loc	1 689 40                @ ../crypto/hrss/hrss.c:689:40
	veor	q8, q12, q13
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #624
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q8, q14, q8
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #448
	.loc	1 691 12 is_stmt 1      @ ../crypto/hrss/hrss.c:691:12
	veor	q12, q8, q12
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #16
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q9, q4, q15
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #448
	.loc	1 685 30 is_stmt 0      @ ../crypto/hrss/hrss.c:685:30
	vand	q9, q14, q9
.Ltmp63:
	.loc	1 701 44 is_stmt 1      @ ../crypto/hrss/hrss.c:701:44
	vand	q11, q12, q0
.Ltmp64:
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q4, q9, q4
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q9, q9, q15
.Ltmp65:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q10, q4, q3
	vst1.64	{d8, d9}, [r0:128]      @ 16-byte Spill
	add	r0, sp, #672
	.loc	1 701 38 is_stmt 0      @ ../crypto/hrss/hrss.c:701:38
	veor	q10, q11, q10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp66:
	.loc	1 690 12 is_stmt 1      @ ../crypto/hrss/hrss.c:690:12
	veor	q8, q8, q13
.Ltmp67:
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q11, q4, q0
.Ltmp68:
	.loc	1 225 15                @ ../crypto/hrss/hrss.c:225:15
	add	r0, sp, #64
.Ltmp69:
	.loc	1 702 44                @ ../crypto/hrss/hrss.c:702:44
	vand	q12, q12, q3
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q13, q8, q9
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q11, q12, q11
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q15, q10, q9
	.loc	1 708 41 is_stmt 0      @ ../crypto/hrss/hrss.c:708:41
	vbic	q12, q11, q13
	.loc	1 708 35                @ ../crypto/hrss/hrss.c:708:35
	veor	q12, q12, q15
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q15, q10, q11
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q10, q10, q13
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q4, q8, q15
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q8, q11, q8
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q12, q12, q4
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q9, q9, q15
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q8, q10, q8
.Ltmp70:
	.loc	1 224 12 is_stmt 1      @ ../crypto/hrss/hrss.c:224:12
	vshr.u16	q4, q12, #1
	.loc	1 223 33                @ ../crypto/hrss/hrss.c:223:33
	vshl.i16	q12, q12, #15
.Ltmp71:
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q8, q8, q9
	vmov.i32	q11, #0x0
.Ltmp72:
	.loc	1 225 15                @ ../crypto/hrss/hrss.c:225:15
	vext.16	q5, q12, q2, #1
	.loc	1 218 12                @ ../crypto/hrss/hrss.c:218:12
	vshr.u16	q9, q8, #1
	.loc	1 225 15                @ ../crypto/hrss/hrss.c:225:15
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 226 12                @ ../crypto/hrss/hrss.c:226:12
	vorr	q12, q5, q4
.Ltmp73:
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #656
.Ltmp74:
	.loc	1 217 33                @ ../crypto/hrss/hrss.c:217:33
	vshl.i16	q8, q8, #15
.Ltmp75:
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp76:
	.loc	1 219 15                @ ../crypto/hrss/hrss.c:219:15
	add	r0, sp, #48
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	add	r0, sp, #624
	.loc	1 219 15                @ ../crypto/hrss/hrss.c:219:15
	vext.16	q8, q8, q2, #1
	.loc	1 220 12                @ ../crypto/hrss/hrss.c:220:12
	vorr	q8, q8, q9
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #32
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #592
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #432
	vshr.u16	q8, q8, #1
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #512
.Ltmp77:
	.loc	1 689 40                @ ../crypto/hrss/hrss.c:689:40
	veor	q9, q12, q4
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #400
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q9, q14, q9
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	.loc	1 685 40 is_stmt 1      @ ../crypto/hrss/hrss.c:685:40
	veor	q10, q2, q5
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q12, q9, q12
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q14, q10
.Ltmp78:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q15, q12, q0
.Ltmp79:
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q2, q10, q2
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q5
.Ltmp80:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q13, q2, q3
.Ltmp81:
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q9, q9, q4
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
.Ltmp82:
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q13, q15, q13
	add	r0, sp, #592
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q15, q2, q0
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q2, q12, q3
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 705 31 is_stmt 1      @ ../crypto/hrss/hrss.c:705:31
	vorr	q4, q9, q10
.Ltmp83:
	.loc	1 225 15                @ ../crypto/hrss/hrss.c:225:15
	add	r0, sp, #384
.Ltmp84:
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q15, q2, q15
.Ltmp85:
	.loc	1 225 15                @ ../crypto/hrss/hrss.c:225:15
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
.Ltmp86:
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q5, q13, q10
.Ltmp87:
	.loc	1 218 12                @ ../crypto/hrss/hrss.c:218:12
	add	r0, sp, #384
.Ltmp88:
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q2, q15, q4
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q2, q2, q5
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q5, q13, q15
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q13, q13, q4
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q6, q9, q5
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q9, q15, q9
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q6, q2, q6
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q10, q10, q5
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q9, q13, q9
.Ltmp89:
	.loc	1 223 33 is_stmt 1      @ ../crypto/hrss/hrss.c:223:33
	vshl.i16	q2, q6, #15
	.loc	1 227 15                @ ../crypto/hrss/hrss.c:227:15
	vext.16	q7, q11, q2, #1
	.loc	1 225 12                @ ../crypto/hrss/hrss.c:225:12
	vorr	q8, q7, q8
	.loc	1 225 15 is_stmt 0      @ ../crypto/hrss/hrss.c:225:15
	vext.16	q7, q12, q11, #1
	.loc	1 226 12 is_stmt 1      @ ../crypto/hrss/hrss.c:226:12
	vorr	q8, q8, q7
	.loc	1 218 12                @ ../crypto/hrss/hrss.c:218:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshr.u16	q8, q1, #1
.Ltmp90:
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q1, q9, q10
.Ltmp91:
	.loc	1 219 15                @ ../crypto/hrss/hrss.c:219:15
	add	r0, sp, #352
	.loc	1 217 33                @ ../crypto/hrss/hrss.c:217:33
	vshl.i16	q13, q1, #15
	.loc	1 221 15                @ ../crypto/hrss/hrss.c:221:15
	vext.16	q9, q11, q13, #1
	.loc	1 219 12                @ ../crypto/hrss/hrss.c:219:12
	vorr	q8, q9, q8
	.loc	1 219 15 is_stmt 0      @ ../crypto/hrss/hrss.c:219:15
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 224 12 is_stmt 1      @ ../crypto/hrss/hrss.c:224:12
	add	r0, sp, #352
	.loc	1 219 15                @ ../crypto/hrss/hrss.c:219:15
	vext.16	q9, q9, q11, #1
	vmov.i32	q11, #0x0
	.loc	1 220 12                @ ../crypto/hrss/hrss.c:220:12
	vorr	q8, q8, q9
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #576
	vshr.u16	q8, q6, #1
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #496
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #480
.Ltmp92:
	.loc	1 689 40                @ ../crypto/hrss/hrss.c:689:40
	veor	q9, q12, q5
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #416
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q9, q14, q9
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #480
	.loc	1 685 40 is_stmt 1      @ ../crypto/hrss/hrss.c:685:40
	veor	q10, q4, q6
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q12, q9, q12
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q14, q10
.Ltmp93:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q15, q12, q0
.Ltmp94:
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q4, q10, q4
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q6
.Ltmp95:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q14, q4, q3
.Ltmp96:
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q9, q9, q5
	vst1.64	{d8, d9}, [r0:128]      @ 16-byte Spill
.Ltmp97:
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q15, q15, q14
	add	r0, sp, #576
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q14, q4, q0
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q4, q12, q3
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 705 31 is_stmt 1      @ ../crypto/hrss/hrss.c:705:31
	vorr	q5, q9, q10
.Ltmp98:
	.loc	1 218 12                @ ../crypto/hrss/hrss.c:218:12
	add	r0, sp, #432
.Ltmp99:
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q4, q4, q14
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q6, q15, q10
	.loc	1 708 41 is_stmt 0      @ ../crypto/hrss/hrss.c:708:41
	vbic	q14, q4, q5
	.loc	1 708 35                @ ../crypto/hrss/hrss.c:708:35
	veor	q14, q14, q6
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q6, q15, q4
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q7, q9, q6
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q9, q4, q9
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q7, q14, q7
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q10, q10, q6
.Ltmp100:
	.loc	1 223 33                @ ../crypto/hrss/hrss.c:223:33
	vshl.i16	q14, q7, #15
	.loc	1 227 15                @ ../crypto/hrss/hrss.c:227:15
	vext.16	q12, q11, q14, #1
	.loc	1 225 12                @ ../crypto/hrss/hrss.c:225:12
	vorr	q8, q12, q8
	.loc	1 225 15 is_stmt 0      @ ../crypto/hrss/hrss.c:225:15
	vext.16	q12, q2, q11, #1
	.loc	1 226 12 is_stmt 1      @ ../crypto/hrss/hrss.c:226:12
	vorr	q8, q8, q12
	.loc	1 225 15                @ ../crypto/hrss/hrss.c:225:15
	vext.16	q14, q14, q11, #1
.Ltmp101:
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q12, q15, q5
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q9, q12, q9
.Ltmp102:
	.loc	1 218 12 is_stmt 1      @ ../crypto/hrss/hrss.c:218:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshr.u16	q8, q1, #1
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	add	r0, sp, #400
.Ltmp103:
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q2, q9, q10
.Ltmp104:
	.loc	1 217 33                @ ../crypto/hrss/hrss.c:217:33
	vshl.i16	q1, q2, #15
	.loc	1 221 15                @ ../crypto/hrss/hrss.c:221:15
	vext.16	q9, q11, q1, #1
	.loc	1 219 12                @ ../crypto/hrss/hrss.c:219:12
	vorr	q8, q9, q8
	.loc	1 219 15 is_stmt 0      @ ../crypto/hrss/hrss.c:219:15
	vext.16	q9, q13, q11, #1
	.loc	1 220 12 is_stmt 1      @ ../crypto/hrss/hrss.c:220:12
	vorr	q8, q8, q9
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #640
	vshr.u16	q8, q7, #1
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #560
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #928
.Ltmp105:
	.loc	1 689 40                @ ../crypto/hrss/hrss.c:689:40
	veor	q9, q15, q4
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #544
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q9, q12, q9
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #464
	.loc	1 691 12 is_stmt 1      @ ../crypto/hrss/hrss.c:691:12
	veor	q15, q9, q15
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #464
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q10, q6, q5
.Ltmp106:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q13, q15, q0
.Ltmp107:
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q12, q10
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q9, q9, q4
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q6, q10, q6
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q5
.Ltmp108:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q12, q6, q3
	vst1.64	{d12, d13}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #560
	.loc	1 701 38 is_stmt 0      @ ../crypto/hrss/hrss.c:701:38
	veor	q12, q13, q12
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	.loc	1 702 33 is_stmt 1      @ ../crypto/hrss/hrss.c:702:33
	vand	q13, q6, q0
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q15, q15, q3
.Ltmp109:
	.loc	1 218 12 is_stmt 1      @ ../crypto/hrss/hrss.c:218:12
	add	r0, sp, #496
.Ltmp110:
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q5, q12, q10
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q13, q15, q13
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q15, q9, q10
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q4, q13, q15
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q4, q4, q5
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q5, q12, q13
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q12, q12, q15
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q6, q9, q5
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q9, q13, q9
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q4, q4, q6
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q10, q10, q5
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q9, q12, q9
.Ltmp111:
	.loc	1 223 33 is_stmt 1      @ ../crypto/hrss/hrss.c:223:33
	vshl.i16	q6, q4, #15
.Ltmp112:
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q9, q9, q10
	vmov.i32	q13, #0x0
.Ltmp113:
	.loc	1 227 15                @ ../crypto/hrss/hrss.c:227:15
	vext.16	q7, q11, q6, #1
	vmov.i32	q11, #0x0
	.loc	1 217 33                @ ../crypto/hrss/hrss.c:217:33
	vshl.i16	q10, q9, #15
	.loc	1 225 12                @ ../crypto/hrss/hrss.c:225:12
	vorr	q8, q7, q8
	.loc	1 218 12                @ ../crypto/hrss/hrss.c:218:12
	vshr.u16	q9, q9, #1
	.loc	1 226 12                @ ../crypto/hrss/hrss.c:226:12
	vorr	q8, q8, q14
	.loc	1 221 15                @ ../crypto/hrss/hrss.c:221:15
	vext.16	q12, q13, q10, #1
	.loc	1 218 12                @ ../crypto/hrss/hrss.c:218:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshr.u16	q8, q2, #1
	.loc	1 227 15                @ ../crypto/hrss/hrss.c:227:15
	add	r0, sp, #416
	.loc	1 219 12                @ ../crypto/hrss/hrss.c:219:12
	vorr	q8, q12, q8
	.loc	1 219 15 is_stmt 0      @ ../crypto/hrss/hrss.c:219:15
	vext.16	q12, q1, q13, #1
	.loc	1 220 12 is_stmt 1      @ ../crypto/hrss/hrss.c:220:12
	vorr	q8, q8, q12
	.loc	1 224 12                @ ../crypto/hrss/hrss.c:224:12
	vshr.u16	q12, q4, #1
	.loc	1 227 15                @ ../crypto/hrss/hrss.c:227:15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #64
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	.loc	1 221 15                @ ../crypto/hrss/hrss.c:221:15
	add	r0, sp, #640
	.loc	1 227 15                @ ../crypto/hrss/hrss.c:227:15
	vext.16	q8, q13, q8, #1
	.loc	1 225 12                @ ../crypto/hrss/hrss.c:225:12
	vorr	q8, q8, q12
	.loc	1 225 15 is_stmt 0      @ ../crypto/hrss/hrss.c:225:15
	vext.16	q12, q6, q13, #1
	.loc	1 226 12 is_stmt 1      @ ../crypto/hrss/hrss.c:226:12
	vorr	q8, q8, q12
	.loc	1 221 15                @ ../crypto/hrss/hrss.c:221:15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #48
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
.Ltmp114:
	.loc	1 689 40                @ ../crypto/hrss/hrss.c:689:40
	add	r0, sp, #544
.Ltmp115:
	.loc	1 221 15                @ ../crypto/hrss/hrss.c:221:15
	vext.16	q8, q13, q8, #1
	.loc	1 219 12                @ ../crypto/hrss/hrss.c:219:12
	vorr	q8, q8, q9
	.loc	1 219 15 is_stmt 0      @ ../crypto/hrss/hrss.c:219:15
	vext.16	q9, q10, q11, #1
	.loc	1 220 12 is_stmt 1      @ ../crypto/hrss/hrss.c:220:12
	vorr	q8, q8, q9
.Ltmp116:
	.loc	1 689 40                @ ../crypto/hrss/hrss.c:689:40
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #864
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #928
	veor	q8, q9, q13
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q8, q7, q8
.Ltmp117:
	.loc	1 714 3 is_stmt 1       @ ../crypto/hrss/hrss.c:714:3
	vmov.32	r4, d14[0]
.Ltmp118:
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q15, q8, q9
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q8, q8, q13
.Ltmp119:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q11, q15, q0
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 701 32 is_stmt 0      @ ../crypto/hrss/hrss.c:701:32
	add	r0, sp, #240
.Ltmp120:
	.loc	1 685 40 is_stmt 1      @ ../crypto/hrss/hrss.c:685:40
	veor	q9, q10, q14
	.loc	1 685 30 is_stmt 0      @ ../crypto/hrss/hrss.c:685:30
	vand	q9, q7, q9
	.loc	1 687 12 is_stmt 1      @ ../crypto/hrss/hrss.c:687:12
	veor	q12, q9, q10
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q9, q9, q14
.Ltmp121:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q10, q12, q3
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #864
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q10, q11, q10
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q11, q12, q0
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q12, q15, q3
.Ltmp122:
	.loc	1 766 52 is_stmt 1      @ ../crypto/hrss/hrss.c:766:52
	and.w	r3, r3, r4
.Ltmp123:
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q14, q10, q9
.Ltmp124:
	.loc	1 767 11                @ ../crypto/hrss/hrss.c:767:11
	eor.w	r5, r5, r3
.Ltmp125:
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q11, q12, q11
.Ltmp126:
	.loc	2 304 30                @ ../crypto/hrss/../internal.h:304:30
	add.w	r4, r5, r12
.Ltmp127:
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q12, q8, q9
.Ltmp128:
	.loc	1 768 11                @ ../crypto/hrss/hrss.c:768:11
	eor.w	r6, r6, r3
.Ltmp129:
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q13, q11, q12
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q13, q13, q14
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q14, q10, q11
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q10, q10, q12
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q15, q8, q14
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q8, q11, q8
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q13, q13, q15
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q9, q9, q14
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q8, q10, q8
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q8, q8, q9
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #848
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #288
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #288
.Ltmp130:
	.loc	1 689 40 is_stmt 1      @ ../crypto/hrss/hrss.c:689:40
	veor	q8, q10, q14
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q9, q7, q8
	.loc	1 691 12 is_stmt 1      @ ../crypto/hrss/hrss.c:691:12
	veor	q13, q9, q10
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q9, q9, q14
.Ltmp131:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q12, q13, q0
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #784
	.loc	1 702 44                @ ../crypto/hrss/hrss.c:702:44
	vand	q13, q13, q3
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #272
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	add	r0, sp, #272
.Ltmp132:
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q8, q11, q15
	.loc	1 685 30 is_stmt 0      @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q7, q8
	.loc	1 687 12 is_stmt 1      @ ../crypto/hrss/hrss.c:687:12
	veor	q8, q10, q11
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q15
.Ltmp133:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q11, q8, q3
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #848
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q11, q12, q11
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q12, q8, q0
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q15, q11, q10
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q12, q13, q12
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q13, q9, q10
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q14, q12, q13
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q14, q14, q15
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q15, q11, q12
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q11, q11, q13
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q4, q9, q15
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q9, q12, q9
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q8, q14, q4
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q10, q10, q15
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q9, q11, q9
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #784
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q8, q9, q10
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #832
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #320
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #752
.Ltmp134:
	.loc	1 689 40 is_stmt 1      @ ../crypto/hrss/hrss.c:689:40
	veor	q9, q10, q8
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #304
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q9, q7, q9
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp135:
	.loc	1 701 32 is_stmt 1      @ ../crypto/hrss/hrss.c:701:32
	add	r0, sp, #304
.Ltmp136:
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q12, q9, q10
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q10, q11, q15
.Ltmp137:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q13, q12, q0
.Ltmp138:
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q7, q10
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q9, q9, q8
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q14, q10, q11
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q15
.Ltmp139:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q11, q14, q3
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #832
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q11, q13, q11
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q13, q14, q0
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q14, q12, q3
	.loc	1 708 22 is_stmt 1      @ ../crypto/hrss/hrss.c:708:22
	vand	q4, q11, q10
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q13, q14, q13
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q14, q9, q10
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q15, q13, q14
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q15, q15, q4
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q4, q11, q13
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q11, q11, q14
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q5, q9, q4
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q9, q13, q9
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q8, q15, q5
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q10, q10, q4
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q9, q11, q9
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #752
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q8, q9, q10
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #224
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
.Ltmp140:
	.loc	1 689 40 is_stmt 1      @ ../crypto/hrss/hrss.c:689:40
	veor	q9, q10, q8
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #336
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q9, q7, q9
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp141:
	.loc	1 707 60 is_stmt 1      @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #816
.Ltmp142:
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q14, q9, q10
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q10, q11, q1
.Ltmp143:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q15, q14, q0
.Ltmp144:
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q7, q10
.Ltmp145:
	.loc	1 702 44                @ ../crypto/hrss/hrss.c:702:44
	vand	q4, q14, q3
.Ltmp146:
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q11, q10, q11
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q1
.Ltmp147:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q13, q11, q3
.Ltmp148:
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q9, q9, q8
.Ltmp149:
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q13, q15, q13
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q15, q11, q0
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q1, q13, q10
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q15, q4, q15
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q4, q9, q10
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q5, q15, q4
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q1, q5, q1
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q5, q13, q15
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q13, q13, q4
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q2, q9, q5
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q9, q15, q9
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q8, q1, q2
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q10, q10, q5
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q9, q13, q9
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #736
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q8, q9, q10
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #96
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #720
.Ltmp150:
	.loc	1 689 40 is_stmt 1      @ ../crypto/hrss/hrss.c:689:40
	veor	q9, q10, q8
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #128
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q9, q7, q9
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
.Ltmp151:
	.loc	1 707 60 is_stmt 1      @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #800
.Ltmp152:
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q4, q9, q10
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q10, q13, q5
.Ltmp153:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q1, q4, q0
.Ltmp154:
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q7, q10
.Ltmp155:
	.loc	1 702 44                @ ../crypto/hrss/hrss.c:702:44
	vand	q2, q4, q3
.Ltmp156:
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q13, q10, q13
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q5
.Ltmp157:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q15, q13, q3
.Ltmp158:
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q9, q9, q8
.Ltmp159:
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q15, q1, q15
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q1, q13, q0
	.loc	1 708 22                @ ../crypto/hrss/hrss.c:708:22
	vand	q8, q15, q10
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q1, q2, q1
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q2, q9, q10
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q5, q1, q2
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q8, q5, q8
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q5, q15, q1
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q6, q9, q5
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q9, q1, q9
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q8, q8, q6
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vbic	q8, q10, q5
	.loc	1 707 41 is_stmt 0      @ ../crypto/hrss/hrss.c:707:41
	vbic	q10, q15, q2
.Ltmp160:
	.loc	1 689 40 is_stmt 1      @ ../crypto/hrss/hrss.c:689:40
	add	r0, sp, #720
.Ltmp161:
	.loc	1 707 35                @ ../crypto/hrss/hrss.c:707:35
	veor	q9, q10, q9
	.loc	1 707 54 is_stmt 0      @ ../crypto/hrss/hrss.c:707:54
	veor	q8, q9, q8
.Ltmp162:
	.loc	1 689 40 is_stmt 1      @ ../crypto/hrss/hrss.c:689:40
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #704
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #208
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #368
	veor	q8, q9, q5
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #688
	.loc	1 689 30 is_stmt 0      @ ../crypto/hrss/hrss.c:689:30
	vand	q8, q7, q8
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
.Ltmp163:
	.loc	1 707 60 is_stmt 1      @ ../crypto/hrss/hrss.c:707:60
	add	r0, sp, #704
.Ltmp164:
	.loc	1 685 40                @ ../crypto/hrss/hrss.c:685:40
	veor	q10, q15, q6
	.loc	1 691 12                @ ../crypto/hrss/hrss.c:691:12
	veor	q9, q8, q9
	.loc	1 685 30                @ ../crypto/hrss/hrss.c:685:30
	vand	q10, q7, q10
.Ltmp165:
	.loc	1 701 44                @ ../crypto/hrss/hrss.c:701:44
	vand	q2, q9, q0
.Ltmp166:
	.loc	1 687 12                @ ../crypto/hrss/hrss.c:687:12
	veor	q15, q10, q15
	.loc	1 686 12                @ ../crypto/hrss/hrss.c:686:12
	veor	q10, q10, q6
.Ltmp167:
	.loc	1 701 32                @ ../crypto/hrss/hrss.c:701:32
	vand	q1, q15, q3
.Ltmp168:
	.loc	1 690 12                @ ../crypto/hrss/hrss.c:690:12
	veor	q8, q8, q5
.Ltmp169:
	.loc	1 701 38                @ ../crypto/hrss/hrss.c:701:38
	veor	q1, q2, q1
	.loc	1 702 33                @ ../crypto/hrss/hrss.c:702:33
	vand	q2, q15, q0
	.loc	1 702 44 is_stmt 0      @ ../crypto/hrss/hrss.c:702:44
	vand	q0, q9, q3
	.loc	1 708 22 is_stmt 1      @ ../crypto/hrss/hrss.c:708:22
	vand	q5, q1, q10
	.loc	1 702 38                @ ../crypto/hrss/hrss.c:702:38
	veor	q0, q0, q2
	.loc	1 705 31                @ ../crypto/hrss/hrss.c:705:31
	vorr	q2, q8, q10
	.loc	1 708 41                @ ../crypto/hrss/hrss.c:708:41
	vbic	q3, q0, q2
	.loc	1 708 35 is_stmt 0      @ ../crypto/hrss/hrss.c:708:35
	veor	q3, q3, q5
	.loc	1 706 34 is_stmt 1      @ ../crypto/hrss/hrss.c:706:34
	vorr	q5, q1, q0
	.loc	1 707 41                @ ../crypto/hrss/hrss.c:707:41
	vbic	q1, q1, q2
	.loc	1 708 60                @ ../crypto/hrss/hrss.c:708:60
	vbic	q6, q8, q5
	.loc	1 707 22                @ ../crypto/hrss/hrss.c:707:22
	vand	q8, q0, q8
	.loc	1 708 54                @ ../crypto/hrss/hrss.c:708:54
	veor	q3, q3, q6
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vbic	q10, q10, q5
	.loc	1 707 35 is_stmt 0      @ ../crypto/hrss/hrss.c:707:35
	veor	q8, q1, q8
	.loc	1 707 60                @ ../crypto/hrss/hrss.c:707:60
	vst1.64	{d6, d7}, [r0:128]      @ 16-byte Spill
.Ltmp170:
	.loc	1 203 33 is_stmt 1      @ ../crypto/hrss/hrss.c:203:33
	vshr.u16	q0, q9, #15
.Ltmp171:
	.loc	1 707 54                @ ../crypto/hrss/hrss.c:707:54
	veor	q8, q8, q10
.Ltmp172:
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	add	r0, sp, #688
	vmov.i32	q3, #0x0
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q9, #1
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	add	r0, sp, #208
	.loc	1 205 15                @ ../crypto/hrss/hrss.c:205:15
	vext.16	q9, q3, q0, #7
	.loc	1 206 12                @ ../crypto/hrss/hrss.c:206:12
	vorr	q8, q9, q8
	.loc	1 195 33                @ ../crypto/hrss/hrss.c:195:33
	vshr.u16	q9, q15, #15
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q15, #1
	.loc	1 203 33                @ ../crypto/hrss/hrss.c:203:33
	add	r0, sp, #368
	.loc	1 198 15                @ ../crypto/hrss/hrss.c:198:15
	vext.16	q10, q3, q9, #7
	.loc	1 199 12                @ ../crypto/hrss/hrss.c:199:12
	vorr	q8, q10, q8
	.loc	1 203 33                @ ../crypto/hrss/hrss.c:203:33
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #288
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vshr.u16	q8, q5, #15
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	.loc	1 195 33                @ ../crypto/hrss/hrss.c:195:33
	add	r0, sp, #256
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	vshl.i16	q10, q1, #1
	.loc	1 207 15                @ ../crypto/hrss/hrss.c:207:15
	vext.16	q15, q8, q3, #7
	.loc	1 205 12                @ ../crypto/hrss/hrss.c:205:12
	vorr	q10, q15, q10
	.loc	1 205 15 is_stmt 0      @ ../crypto/hrss/hrss.c:205:15
	vext.16	q8, q3, q8, #7
	.loc	1 203 33 is_stmt 1      @ ../crypto/hrss/hrss.c:203:33
	vshr.u16	q15, q1, #15
	.loc	1 205 15                @ ../crypto/hrss/hrss.c:205:15
	vext.16	q15, q3, q15, #7
	.loc	1 206 12                @ ../crypto/hrss/hrss.c:206:12
	vorr	q10, q10, q15
	.loc	1 195 33                @ ../crypto/hrss/hrss.c:195:33
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #272
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
	vshr.u16	q10, q6, #15
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	add	r0, sp, #240
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	vshl.i16	q15, q2, #1
	.loc	1 201 15                @ ../crypto/hrss/hrss.c:201:15
	vext.16	q1, q10, q3, #7
	.loc	1 198 12                @ ../crypto/hrss/hrss.c:198:12
	vorr	q15, q1, q15
	.loc	1 198 15 is_stmt 0      @ ../crypto/hrss/hrss.c:198:15
	vext.16	q10, q3, q10, #7
	.loc	1 195 33 is_stmt 1      @ ../crypto/hrss/hrss.c:195:33
	vshr.u16	q1, q2, #15
	.loc	1 198 15                @ ../crypto/hrss/hrss.c:198:15
	vext.16	q1, q3, q1, #7
	.loc	1 199 12                @ ../crypto/hrss/hrss.c:199:12
	vorr	q15, q15, q1
	.loc	1 203 33                @ ../crypto/hrss/hrss.c:203:33
	vshr.u16	q1, q12, #15
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	vshl.i16	q15, q5, #1
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	add	r0, sp, #288
	.loc	1 207 15                @ ../crypto/hrss/hrss.c:207:15
	vext.16	q2, q1, q3, #7
	.loc	1 205 12                @ ../crypto/hrss/hrss.c:205:12
	vorr	q15, q2, q15
	.loc	1 206 12                @ ../crypto/hrss/hrss.c:206:12
	vorr	q8, q15, q8
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vshl.i16	q8, q6, #1
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #80
	.loc	1 195 33                @ ../crypto/hrss/hrss.c:195:33
	vshr.u16	q15, q5, #15
	.loc	1 201 15                @ ../crypto/hrss/hrss.c:201:15
	vext.16	q2, q15, q3, #7
	.loc	1 198 12                @ ../crypto/hrss/hrss.c:198:12
	vorr	q8, q2, q8
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	add	r0, sp, #272
	.loc	1 199 12                @ ../crypto/hrss/hrss.c:199:12
	vorr	q8, q8, q10
	.loc	1 198 15                @ ../crypto/hrss/hrss.c:198:15
	vext.16	q15, q3, q15, #7
	.loc	1 203 33                @ ../crypto/hrss/hrss.c:203:33
	vshr.u16	q10, q14, #15
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q12, #1
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	add	r0, sp, #320
	.loc	1 207 15                @ ../crypto/hrss/hrss.c:207:15
	vext.16	q12, q10, q3, #7
	.loc	1 205 12                @ ../crypto/hrss/hrss.c:205:12
	vorr	q8, q12, q8
	.loc	1 205 15 is_stmt 0      @ ../crypto/hrss/hrss.c:205:15
	vext.16	q12, q3, q1, #7
	.loc	1 206 12 is_stmt 1      @ ../crypto/hrss/hrss.c:206:12
	vorr	q8, q8, q12
	.loc	1 205 15                @ ../crypto/hrss/hrss.c:205:15
	vext.16	q10, q3, q10, #7
	.loc	1 195 33                @ ../crypto/hrss/hrss.c:195:33
	vshr.u16	q12, q11, #15
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q5, #1
	add	r0, sp, #160
	.loc	1 201 15                @ ../crypto/hrss/hrss.c:201:15
	vext.16	q1, q12, q3, #7
	.loc	1 198 12                @ ../crypto/hrss/hrss.c:198:12
	vorr	q8, q1, q8
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	add	r0, sp, #304
	.loc	1 199 12                @ ../crypto/hrss/hrss.c:199:12
	vorr	q8, q8, q15
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q14, #1
	.loc	1 203 33                @ ../crypto/hrss/hrss.c:203:33
	vshr.u16	q14, q4, #15
	add	r0, sp, #112
	.loc	1 207 15                @ ../crypto/hrss/hrss.c:207:15
	vext.16	q15, q14, q3, #7
	.loc	1 205 12                @ ../crypto/hrss/hrss.c:205:12
	vorr	q8, q15, q8
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	add	r0, sp, #224
	.loc	1 206 12                @ ../crypto/hrss/hrss.c:206:12
	vorr	q8, q8, q10
	.loc	1 195 33                @ ../crypto/hrss/hrss.c:195:33
	vshr.u16	q10, q13, #15
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q11, #1
	.loc	1 207 15                @ ../crypto/hrss/hrss.c:207:15
	add	r0, sp, #336
	.loc	1 201 15                @ ../crypto/hrss/hrss.c:201:15
	vext.16	q11, q10, q3, #7
	.loc	1 198 12                @ ../crypto/hrss/hrss.c:198:12
	vorr	q8, q11, q8
	.loc	1 198 15 is_stmt 0      @ ../crypto/hrss/hrss.c:198:15
	vext.16	q11, q3, q12, #7
	vmov.i32	q12, #0x0
	.loc	1 199 12 is_stmt 1      @ ../crypto/hrss/hrss.c:199:12
	vorr	q8, q8, q11
	.loc	1 204 12                @ ../crypto/hrss/hrss.c:204:12
	vshl.i16	q11, q4, #1
	.loc	1 207 15                @ ../crypto/hrss/hrss.c:207:15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #176
	vext.16	q8, q0, q3, #7
	.loc	1 205 12                @ ../crypto/hrss/hrss.c:205:12
	vorr	q8, q8, q11
	.loc	1 205 15 is_stmt 0      @ ../crypto/hrss/hrss.c:205:15
	vext.16	q11, q3, q14, #7
	.loc	1 206 12 is_stmt 1      @ ../crypto/hrss/hrss.c:206:12
	vorr	q11, q8, q11
	.loc	1 201 15                @ ../crypto/hrss/hrss.c:201:15
	vext.16	q8, q9, q3, #7
	.loc	1 196 12                @ ../crypto/hrss/hrss.c:196:12
	vshl.i16	q9, q13, #1
	.loc	1 198 12                @ ../crypto/hrss/hrss.c:198:12
	vorr	q8, q8, q9
	.loc	1 198 15 is_stmt 0      @ ../crypto/hrss/hrss.c:198:15
	vext.16	q9, q12, q10, #7
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp173:
	.loc	2 304 38 is_stmt 1      @ ../crypto/hrss/../internal.h:304:38
	sub.w	r0, r5, #2
	.loc	2 304 33 is_stmt 0      @ ../crypto/hrss/../internal.h:304:33
	and.w	r0, r0, r4
.Ltmp174:
	.loc	1 199 12 is_stmt 1      @ ../crypto/hrss/hrss.c:199:12
	vorr	q12, q8, q9
.Ltmp175:
	.loc	1 770 10                @ ../crypto/hrss/hrss.c:770:10
	sub.w	r5, r5, #1
.Ltmp176:
	.loc	2 234 13                @ ../crypto/hrss/../internal.h:234:13
	asr.w	r0, r0, #31
.Ltmp177:
	.loc	1 153 50                @ ../crypto/hrss/hrss.c:153:50
	vdup.16	q8, r0
	add	r0, sp, #192
.Ltmp178:
	.loc	1 782 19                @ ../crypto/hrss/hrss.c:782:19
	vmvn	q9, q8
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
.Ltmp179:
	.loc	1 714 3                 @ ../crypto/hrss/hrss.c:714:3
	add	r0, sp, #912
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
.Ltmp180:
	.loc	1 714 3 is_stmt 0       @ ../crypto/hrss/hrss.c:714:3
	add	r0, sp, #144
	vorr	q14, q9, q9
.Ltmp181:
	.loc	1 714 3                 @ ../crypto/hrss/hrss.c:714:3
	vmov.32	r4, d26[0]
.Ltmp182:
	.loc	1 714 3                 @ ../crypto/hrss/hrss.c:714:3
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
	vmov.32	r0, d26[0]
.Ltmp183:
	.loc	1 775 56 is_stmt 1      @ ../crypto/hrss/hrss.c:775:56
	and.w	r0, r0, r4
	.loc	1 771 12                @ ../crypto/hrss/hrss.c:771:12
	and	r4, r4, #1
	.loc	1 771 7 is_stmt 0       @ ../crypto/hrss/hrss.c:771:7
	add	r1, r4
.Ltmp184:
	.loc	2 343 16 is_stmt 1      @ ../crypto/hrss/../internal.h:343:16
	and.w	r4, r0, r1
	.loc	2 343 30 is_stmt 0      @ ../crypto/hrss/../internal.h:343:30
	bic.w	r0, lr, r0
	.loc	2 343 21                @ ../crypto/hrss/../internal.h:343:21
	orr.w	lr, r0, r4
.Ltmp185:
	.loc	1 747 3 is_stmt 1       @ ../crypto/hrss/hrss.c:747:3
	bne.w	.LBB0_3
@ %bb.4:
	.loc	1 786 3                 @ ../crypto/hrss/hrss.c:786:3
	add	r0, sp, #720
	add.w	r1, r10, #16
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	mov	r5, r10
	.loc	1 787 3                 @ ../crypto/hrss/hrss.c:787:3
	add.w	r9, r10, #88
	.loc	1 786 3                 @ ../crypto/hrss/hrss.c:786:3
	vst1.32	{d16, d17}, [r1]
	add.w	r1, r10, #32
	.loc	1 787 3                 @ ../crypto/hrss/hrss.c:787:3
	mov	r8, r9
	.loc	1 786 3                 @ ../crypto/hrss/hrss.c:786:3
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #752
	vst1.32	{d16, d17}, [r1]
	add.w	r1, r10, #48
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #784
	vst1.32	{d16, d17}, [r1]
	add.w	r1, r10, #64
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #768
	vst1.32	{d16, d17}, [r1]
	.loc	1 787 3                 @ ../crypto/hrss/hrss.c:787:3
	movs	r1, #104
	.loc	1 786 3                 @ ../crypto/hrss/hrss.c:786:3
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #688
	vstr	d16, [r10, #80]
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	.loc	1 787 3                 @ ../crypto/hrss/hrss.c:787:3
	add	r0, sp, #800
	.loc	1 786 3                 @ ../crypto/hrss/hrss.c:786:3
	vst1.16	{d16, d17}, [r5], r1
	.loc	1 787 3                 @ ../crypto/hrss/hrss.c:787:3
	add.w	r1, r10, #120
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #816
	vst1.32	{d16, d17}, [r5]
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #832
	vst1.32	{d16, d17}, [r1]
	add.w	r1, r10, #136
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #848
	vst1.32	{d16, d17}, [r1]
	add.w	r1, r10, #152
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #704
	vst1.32	{d16, d17}, [r1]
	movs	r1, #80
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #864
	vst1.16	{d16, d17}, [r8], r1
.Ltmp186:
	.loc	2 270 42                @ ../crypto/hrss/../internal.h:270:42
	movw	r1, #701
	sub.w	r2, r1, lr
	.loc	2 270 38 is_stmt 0      @ ../crypto/hrss/../internal.h:270:38
	orr.w	r2, r2, lr
.Ltmp187:
	.loc	1 787 3 is_stmt 1       @ ../crypto/hrss/hrss.c:787:3
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
.Ltmp188:
	.loc	1 461 3                 @ ../crypto/hrss/hrss.c:461:3
	mov	r0, r10
.Ltmp189:
	.loc	1 785 17                @ ../crypto/hrss/hrss.c:785:17
	and.w	r1, r1, r2, asr #31
	.loc	1 787 3                 @ ../crypto/hrss/hrss.c:787:3
	vstr	d16, [r8]
	.loc	1 785 12                @ ../crypto/hrss/hrss.c:785:12
	sub.w	r6, lr, r1
.Ltmp190:
	.loc	1 461 3                 @ ../crypto/hrss/hrss.c:461:3
	mov	r1, r6
	bl	poly2_rotr_consttime
	.loc	1 462 3                 @ ../crypto/hrss/hrss.c:462:3
	mov	r0, r9
	mov	r1, r6
	bl	poly2_rotr_consttime
.Ltmp191:
	.loc	1 714 3                 @ ../crypto/hrss/hrss.c:714:3
	add.w	lr, sp, #880
.Ltmp192:
	.loc	1 789 3                 @ ../crypto/hrss/hrss.c:789:3
	mov	r0, r10
.Ltmp193:
	.loc	1 714 3                 @ ../crypto/hrss/hrss.c:714:3
	vld1.64	{d16, d17}, [lr:128]    @ 16-byte Reload
.Ltmp194:
	.loc	1 714 3 is_stmt 0       @ ../crypto/hrss/hrss.c:714:3
	add.w	lr, sp, #896
.Ltmp195:
	.loc	1 714 3                 @ ../crypto/hrss/hrss.c:714:3
	vmov.32	r1, d16[0]
.Ltmp196:
	.loc	1 714 3                 @ ../crypto/hrss/hrss.c:714:3
	vld1.64	{d16, d17}, [lr:128]    @ 16-byte Reload
	vmov.32	r2, d16[0]
.Ltmp197:
	.loc	1 789 3 is_stmt 1       @ ../crypto/hrss/hrss.c:789:3
	bl	poly3_mul_const
	movs	r0, #84
.Ltmp198:
	.loc	1 500 44                @ ../crypto/hrss/hrss.c:500:44
	ldr.w	r1, [r10, #84]
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vld1.32	{d19}, [r9], r0
	movs	r6, #112
.Ltmp199:
	.loc	1 791 1                 @ ../crypto/hrss/hrss.c:791:1
	sub.w	r4, r7, #88
.Ltmp200:
	.loc	1 499 44                @ ../crypto/hrss/hrss.c:499:44
	ldr.w	r0, [r9]
.Ltmp201:
	.loc	1 489 35                @ ../crypto/hrss/hrss.c:489:35
	orr.w	r3, r1, r0
.Ltmp202:
	.loc	1 489 75 is_stmt 0      @ ../crypto/hrss/hrss.c:489:75
	sbfx	r2, r0, #28, #1
.Ltmp203:
	.loc	1 504 22 is_stmt 1      @ ../crypto/hrss/hrss.c:504:22
	mov	r0, r10
	vld1.32	{d20}, [r0], r6
.Ltmp204:
	.loc	1 489 75                @ ../crypto/hrss/hrss.c:489:75
	sbfx	r1, r1, #28, #1
.Ltmp205:
	.loc	1 506 27                @ ../crypto/hrss/hrss.c:506:27
	vorr	d21, d19, d20
	.loc	1 503 3                 @ ../crypto/hrss/hrss.c:503:3
	vdup.32	d16, r1
.Ltmp206:
	.loc	1 489 75                @ ../crypto/hrss/hrss.c:489:75
	lsls	r1, r3, #3
.Ltmp207:
	.loc	1 501 21                @ ../crypto/hrss/hrss.c:501:21
	mvn.w	r1, r1, asr #31
	.loc	1 507 20                @ ../crypto/hrss/hrss.c:507:20
	vand	d22, d19, d16
	.loc	1 503 3                 @ ../crypto/hrss/hrss.c:503:3
	vdup.32	d18, r1
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	mov	r1, r10
	.loc	1 507 56 is_stmt 0      @ ../crypto/hrss/hrss.c:507:56
	vand	d23, d20, d18
	.loc	1 503 3 is_stmt 1       @ ../crypto/hrss/hrss.c:503:3
	vdup.32	d17, r2
	.loc	1 507 38                @ ../crypto/hrss/hrss.c:507:38
	vbic	d24, d17, d21
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	movs	r2, #96
	.loc	1 507 32                @ ../crypto/hrss/hrss.c:507:32
	veor	d22, d22, d23
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d25, [r10, #16]
	vldr	d26, [r10, #24]
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d30, d25, d17
	.loc	1 507 50                @ ../crypto/hrss/hrss.c:507:50
	veor	d22, d22, d24
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d23, [r10, #8]
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vst1.32	{d22}, [r1], r2
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d24, d23, d17
	vand	d3, d26, d17
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d22, [r1]
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d20, d20, d17
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d27, [r5]
	.loc	1 506 27                @ ../crypto/hrss/hrss.c:506:27
	vorr	d31, d22, d23
	.loc	1 508 56                @ ../crypto/hrss/hrss.c:508:56
	vand	d28, d22, d18
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d0, [r0]
	.loc	1 506 27                @ ../crypto/hrss/hrss.c:506:27
	vorr	d29, d27, d25
	.loc	1 508 56                @ ../crypto/hrss/hrss.c:508:56
	vand	d1, d27, d18
	.loc	1 506 27                @ ../crypto/hrss/hrss.c:506:27
	vorr	d2, d0, d26
	.loc	1 508 56                @ ../crypto/hrss/hrss.c:508:56
	vand	d4, d0, d18
	.loc	1 508 32 is_stmt 0      @ ../crypto/hrss/hrss.c:508:32
	veor	d24, d28, d24
	.loc	1 508 38                @ ../crypto/hrss/hrss.c:508:38
	vbic	d5, d16, d31
	.loc	1 508 32                @ ../crypto/hrss/hrss.c:508:32
	veor	d30, d1, d30
	.loc	1 508 38                @ ../crypto/hrss/hrss.c:508:38
	vbic	d28, d16, d29
	vbic	d1, d16, d2
	.loc	1 508 32                @ ../crypto/hrss/hrss.c:508:32
	veor	d3, d4, d3
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d24, d24, d5
	.loc	1 508 56                @ ../crypto/hrss/hrss.c:508:56
	vand	d19, d19, d18
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d28, d30, d28
	veor	d30, d3, d1
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d24, [r1]
	.loc	1 508 32                @ ../crypto/hrss/hrss.c:508:32
	veor	d19, d19, d20
	.loc	1 504 22 is_stmt 1      @ ../crypto/hrss/hrss.c:504:22
	vldr	d24, [r10, #32]
	.loc	1 508 38                @ ../crypto/hrss/hrss.c:508:38
	vbic	d21, d16, d21
	.loc	1 507 20                @ ../crypto/hrss/hrss.c:507:20
	vand	d27, d27, d16
	.loc	1 507 56 is_stmt 0      @ ../crypto/hrss/hrss.c:507:56
	vand	d25, d25, d18
	.loc	1 507 20                @ ../crypto/hrss/hrss.c:507:20
	vand	d0, d0, d16
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d26, d26, d18
	vand	d23, d23, d18
	.loc	1 507 20                @ ../crypto/hrss/hrss.c:507:20
	vand	d22, d22, d16
	.loc	1 507 38                @ ../crypto/hrss/hrss.c:507:38
	vbic	d20, d17, d29
	vbic	d29, d17, d31
	.loc	1 505 22 is_stmt 1      @ ../crypto/hrss/hrss.c:505:22
	vldr	d31, [r10, #120]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d28, [r5]
	.loc	1 507 32                @ ../crypto/hrss/hrss.c:507:32
	veor	d22, d22, d23
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d30, [r0]
	.loc	1 507 32                @ ../crypto/hrss/hrss.c:507:32
	veor	d25, d27, d25
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d1, [r10, #128]
	.loc	1 507 32                @ ../crypto/hrss/hrss.c:507:32
	veor	d26, d0, d26
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d30, [r10, #40]
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d19, d19, d21
	.loc	1 507 38                @ ../crypto/hrss/hrss.c:507:38
	vbic	d27, d17, d2
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d23, d24, d17
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d28, d24, d18
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d19, [r10, #88]
	.loc	1 506 27                @ ../crypto/hrss/hrss.c:506:27
	vorr	d21, d1, d30
	.loc	1 507 20                @ ../crypto/hrss/hrss.c:507:20
	vand	d0, d31, d16
	.loc	1 506 27                @ ../crypto/hrss/hrss.c:506:27
	vorr	d24, d31, d24
	.loc	1 508 56                @ ../crypto/hrss/hrss.c:508:56
	vand	d31, d31, d18
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d2, d30, d18
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d4, d30, d17
	.loc	1 507 20                @ ../crypto/hrss/hrss.c:507:20
	vand	d3, d1, d16
	.loc	1 508 56                @ ../crypto/hrss/hrss.c:508:56
	vand	d5, d1, d18
	.loc	1 507 50                @ ../crypto/hrss/hrss.c:507:50
	veor	d20, d25, d20
	veor	d25, d26, d27
	veor	d22, d22, d29
	.loc	1 507 32 is_stmt 0      @ ../crypto/hrss/hrss.c:507:32
	veor	d26, d0, d28
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d20, [r10, #16]
	.loc	1 507 38                @ ../crypto/hrss/hrss.c:507:38
	vbic	d27, d17, d24
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d25, [r10, #24]
	.loc	1 508 32 is_stmt 1      @ ../crypto/hrss/hrss.c:508:32
	veor	d23, d31, d23
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d22, [r10, #8]
	.loc	1 508 38                @ ../crypto/hrss/hrss.c:508:38
	vbic	d24, d16, d24
	.loc	1 507 32                @ ../crypto/hrss/hrss.c:507:32
	veor	d28, d3, d2
	.loc	1 507 38 is_stmt 0      @ ../crypto/hrss/hrss.c:507:38
	vbic	d19, d17, d21
	.loc	1 508 38 is_stmt 1      @ ../crypto/hrss/hrss.c:508:38
	vbic	d30, d16, d21
	.loc	1 508 32 is_stmt 0      @ ../crypto/hrss/hrss.c:508:32
	veor	d29, d5, d4
	.loc	1 507 50 is_stmt 1      @ ../crypto/hrss/hrss.c:507:50
	veor	d20, d26, d27
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d21, d23, d24
	.loc	1 507 50                @ ../crypto/hrss/hrss.c:507:50
	veor	d19, d28, d19
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d22, d29, d30
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d20, [r10, #32]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d21, [r10, #120]
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d19, [r10, #40]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d22, [r10, #128]
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d19, [r10, #48]
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d20, [r10, #136]
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d21, d19, d18
	.loc	1 507 20 is_stmt 0      @ ../crypto/hrss/hrss.c:507:20
	vand	d22, d20, d16
	.loc	1 506 27 is_stmt 1      @ ../crypto/hrss/hrss.c:506:27
	vorr	d23, d20, d19
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d19, d19, d17
	.loc	1 508 56 is_stmt 0      @ ../crypto/hrss/hrss.c:508:56
	vand	d20, d20, d18
	.loc	1 507 32 is_stmt 1      @ ../crypto/hrss/hrss.c:507:32
	veor	d21, d22, d21
	.loc	1 507 38 is_stmt 0      @ ../crypto/hrss/hrss.c:507:38
	vbic	d22, d17, d23
	.loc	1 508 32 is_stmt 1      @ ../crypto/hrss/hrss.c:508:32
	veor	d19, d20, d19
	.loc	1 508 38 is_stmt 0      @ ../crypto/hrss/hrss.c:508:38
	vbic	d20, d16, d23
	.loc	1 507 50 is_stmt 1      @ ../crypto/hrss/hrss.c:507:50
	veor	d21, d21, d22
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d19, d19, d20
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d21, [r10, #48]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d19, [r10, #136]
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d19, [r10, #56]
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d20, [r10, #144]
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d21, d19, d18
	.loc	1 507 20 is_stmt 0      @ ../crypto/hrss/hrss.c:507:20
	vand	d22, d20, d16
	.loc	1 506 27 is_stmt 1      @ ../crypto/hrss/hrss.c:506:27
	vorr	d23, d20, d19
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d19, d19, d17
	.loc	1 508 56 is_stmt 0      @ ../crypto/hrss/hrss.c:508:56
	vand	d20, d20, d18
	.loc	1 507 32 is_stmt 1      @ ../crypto/hrss/hrss.c:507:32
	veor	d21, d22, d21
	.loc	1 507 38 is_stmt 0      @ ../crypto/hrss/hrss.c:507:38
	vbic	d22, d17, d23
	.loc	1 508 32 is_stmt 1      @ ../crypto/hrss/hrss.c:508:32
	veor	d19, d20, d19
	.loc	1 508 38 is_stmt 0      @ ../crypto/hrss/hrss.c:508:38
	vbic	d20, d16, d23
	.loc	1 507 50 is_stmt 1      @ ../crypto/hrss/hrss.c:507:50
	veor	d21, d21, d22
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d19, d19, d20
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d21, [r10, #56]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d19, [r10, #144]
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d19, [r10, #64]
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d20, [r10, #152]
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d21, d19, d18
	.loc	1 507 20 is_stmt 0      @ ../crypto/hrss/hrss.c:507:20
	vand	d22, d20, d16
	.loc	1 506 27 is_stmt 1      @ ../crypto/hrss/hrss.c:506:27
	vorr	d23, d20, d19
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d19, d19, d17
	.loc	1 508 56 is_stmt 0      @ ../crypto/hrss/hrss.c:508:56
	vand	d20, d20, d18
	.loc	1 507 32 is_stmt 1      @ ../crypto/hrss/hrss.c:507:32
	veor	d21, d22, d21
	.loc	1 507 38 is_stmt 0      @ ../crypto/hrss/hrss.c:507:38
	vbic	d22, d17, d23
	.loc	1 508 32 is_stmt 1      @ ../crypto/hrss/hrss.c:508:32
	veor	d19, d20, d19
	.loc	1 508 38 is_stmt 0      @ ../crypto/hrss/hrss.c:508:38
	vbic	d20, d16, d23
	.loc	1 507 50 is_stmt 1      @ ../crypto/hrss/hrss.c:507:50
	veor	d21, d21, d22
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d19, d19, d20
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d21, [r10, #64]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d19, [r10, #152]
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d19, [r10, #72]
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d20, [r10, #160]
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d21, d19, d18
	.loc	1 507 20 is_stmt 0      @ ../crypto/hrss/hrss.c:507:20
	vand	d22, d20, d16
	.loc	1 506 27 is_stmt 1      @ ../crypto/hrss/hrss.c:506:27
	vorr	d23, d20, d19
	.loc	1 508 20                @ ../crypto/hrss/hrss.c:508:20
	vand	d19, d19, d17
	.loc	1 508 56 is_stmt 0      @ ../crypto/hrss/hrss.c:508:56
	vand	d20, d20, d18
	.loc	1 507 32 is_stmt 1      @ ../crypto/hrss/hrss.c:507:32
	veor	d21, d22, d21
	.loc	1 507 38 is_stmt 0      @ ../crypto/hrss/hrss.c:507:38
	vbic	d22, d17, d23
	.loc	1 508 32 is_stmt 1      @ ../crypto/hrss/hrss.c:508:32
	veor	d19, d20, d19
	.loc	1 508 38 is_stmt 0      @ ../crypto/hrss/hrss.c:508:38
	vbic	d20, d16, d23
	.loc	1 507 50 is_stmt 1      @ ../crypto/hrss/hrss.c:507:50
	veor	d21, d21, d22
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d19, d19, d20
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d21, [r10, #72]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d19, [r10, #160]
	.loc	1 505 22                @ ../crypto/hrss/hrss.c:505:22
	vldr	d19, [r8]
	.loc	1 504 22                @ ../crypto/hrss/hrss.c:504:22
	vldr	d20, [r10, #80]
	.loc	1 507 20                @ ../crypto/hrss/hrss.c:507:20
	vand	d22, d19, d16
	.loc	1 506 27                @ ../crypto/hrss/hrss.c:506:27
	vorr	d21, d19, d20
	.loc	1 507 56                @ ../crypto/hrss/hrss.c:507:56
	vand	d23, d20, d18
	.loc	1 508 56                @ ../crypto/hrss/hrss.c:508:56
	vand	d18, d19, d18
	.loc	1 508 20 is_stmt 0      @ ../crypto/hrss/hrss.c:508:20
	vand	d19, d20, d17
	.loc	1 507 38 is_stmt 1      @ ../crypto/hrss/hrss.c:507:38
	vbic	d17, d17, d21
	.loc	1 507 32 is_stmt 0      @ ../crypto/hrss/hrss.c:507:32
	veor	d20, d22, d23
	.loc	1 508 38 is_stmt 1      @ ../crypto/hrss/hrss.c:508:38
	vbic	d16, d16, d21
	.loc	1 508 32 is_stmt 0      @ ../crypto/hrss/hrss.c:508:32
	veor	d18, d18, d19
	.loc	1 507 50 is_stmt 1      @ ../crypto/hrss/hrss.c:507:50
	veor	d17, d20, d17
	.loc	1 508 50                @ ../crypto/hrss/hrss.c:508:50
	veor	d16, d18, d16
	.loc	1 507 15                @ ../crypto/hrss/hrss.c:507:15
	vstr	d17, [r10, #80]
	.loc	1 511 30                @ ../crypto/hrss/hrss.c:511:30
	ldr.w	r0, [r10, #84]
	.loc	1 508 15                @ ../crypto/hrss/hrss.c:508:15
	vstr	d16, [r8]
	.loc	1 512 30                @ ../crypto/hrss/hrss.c:512:30
	ldr.w	r1, [r9]
	.loc	1 511 30                @ ../crypto/hrss/hrss.c:511:30
	bic	r0, r0, #-536870912
	str.w	r0, [r10, #84]
	.loc	1 512 30                @ ../crypto/hrss/hrss.c:512:30
	bic	r0, r1, #-536870912
	str.w	r0, [r9]
.Ltmp208:
	.loc	1 791 1                 @ ../crypto/hrss/hrss.c:791:1
	mov	sp, r4
	vpop	{d8, d9, d10, d11, d12, d13, d14, d15}
	pop.w	{r8, r9, r10}
	pop	{r4, r5, r6, r7, pc}
.Ltmp209:
@ %bb.5:
.Lfunc_end0:
	.size	poly3_invert_vec, .Lfunc_end0-poly3_invert_vec
	.cfi_endproc
	.fnend

	.section	.text.poly_mul_vec,"ax",%progbits
	.hidden	poly_mul_vec            @ -- Begin function poly_mul_vec
	.globl	poly_mul_vec
	.p2align	2
	.type	poly_mul_vec,%function
	.code	16                      @ @poly_mul_vec
	.thumb_func
poly_mul_vec:
.Lfunc_begin2:
	.loc	1 1087 0                @ ../crypto/hrss/hrss.c:1087:0
	.fnstart
	.cfi_startproc
@ %bb.0:
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.setfp	r7, sp, #12
	add	r7, sp, #12
	.cfi_def_cfa r7, 8
	.save	{r8, r9, r11}
	push.w	{r8, r9, r11}
	.cfi_offset r11, -24
	.cfi_offset r9, -28
	.cfi_offset r8, -32
	.pad	#5600
	sub.w	sp, sp, #5600
	mov	r4, sp
	bfc	r4, #0, #4
	mov	sp, r4
	mov	r4, r0
	ldr	r0, .LCPI2_0
	add.w	r8, sp, #12
	movs	r6, #0
.LPC2_0:
	add	r0, pc
	add.w	r5, sp, #2768
	mov	r3, r2
	mov	r2, r1
	ldr.w	r9, [r0]
	ldr.w	r0, [r9]
	str.w	r0, [r8]
.Ltmp218:
	.loc	1 1098 3 prologue_end   @ ../crypto/hrss/hrss.c:1098:3
	movs	r0, #88
.Ltmp219:
	.loc	2 713 10                @ ../crypto/hrss/../internal.h:713:10
	strh.w	r6, [r1, #1406]
	str.w	r6, [r1, #1402]
	add	r1, sp, #16
.Ltmp220:
	.loc	2 713 10 is_stmt 0      @ ../crypto/hrss/../internal.h:713:10
	strh.w	r6, [r3, #1406]
	str.w	r6, [r3, #1402]
.Ltmp221:
	.loc	1 1098 3 is_stmt 1      @ ../crypto/hrss/hrss.c:1098:3
	str	r0, [sp]
	mov	r0, r5
	bl	poly_mul_vec_aux
	add.w	r0, r5, #1392
	.loc	1 1108 24               @ ../crypto/hrss/hrss.c:1108:24
	vld1.64	{d16, d17}, [r0:128]
	mov.w	r0, #1408
.LBB2_1:                                @ =>This Inner Loop Header: Depth=1
	.loc	1 1109 24               @ ../crypto/hrss/hrss.c:1109:24
	adds	r1, r5, r6
	.loc	1 1110 27               @ ../crypto/hrss/hrss.c:1110:27
	vld1.16	{d18, d19}, [r1:128], r0
	.loc	1 1109 24               @ ../crypto/hrss/hrss.c:1109:24
	vld1.64	{d20, d21}, [r1:128]
	.loc	1 1110 17               @ ../crypto/hrss/hrss.c:1110:17
	adds	r1, r4, r6
	.loc	1 1107 24               @ ../crypto/hrss/hrss.c:1107:24
	adds	r6, #16
.Ltmp222:
	.loc	1 181 10                @ ../crypto/hrss/hrss.c:181:10
	vext.16	q8, q8, q10, #5
.Ltmp223:
	.loc	1 1107 3                @ ../crypto/hrss/hrss.c:1107:3
	cmp.w	r6, #1408
.Ltmp224:
	.loc	1 155 58                @ ../crypto/hrss/hrss.c:155:58
	vadd.i16	q8, q8, q9
.Ltmp225:
	.loc	1 1110 17               @ ../crypto/hrss/hrss.c:1110:17
	vst1.64	{d16, d17}, [r1:128]
	.loc	1 1108 24               @ ../crypto/hrss/hrss.c:1108:24
	vorr	q8, q10, q10
	.loc	1 1107 3                @ ../crypto/hrss/hrss.c:1107:3
	bne	.LBB2_1
@ %bb.2:
.Ltmp226:
	.loc	2 713 10                @ ../crypto/hrss/../internal.h:713:10
	movs	r0, #0
	strh.w	r0, [r4, #1406]
	str.w	r0, [r4, #1402]
	ldr.w	r0, [r8]
	ldr.w	r1, [r9]
	subs	r0, r1, r0
.Ltmp227:
	.loc	1 1114 1                @ ../crypto/hrss/hrss.c:1114:1
	itttt	eq
	subeq.w	r4, r7, #24
	moveq	sp, r4
	popeq.w	{r8, r9, r11}
	popeq	{r4, r5, r6, r7, pc}
	bl	__stack_chk_fail
.Ltmp228:
	.p2align	2
@ %bb.3:
	.loc	1 0 1 is_stmt 0         @ ../crypto/hrss/hrss.c:0:1
.LCPI2_0:
.Ltmp229:
	.long	__stack_chk_guard(GOT_PREL)-((.LPC2_0+4)-.Ltmp229)
.Lfunc_end2:
	.size	poly_mul_vec, .Lfunc_end2-poly_mul_vec
	.cfi_endproc
	.fnend
                                        @ -- End function
	.section	.text.poly_mul_vec_aux,"ax",%progbits
	.p2align	1               @ -- Begin function poly_mul_vec_aux
	.type	poly_mul_vec_aux,%function
	.code	16                      @ @poly_mul_vec_aux
	.thumb_func
poly_mul_vec_aux:
.Lfunc_begin3:
	.loc	1 897 0 is_stmt 1       @ ../crypto/hrss/hrss.c:897:0
	.fnstart
	.cfi_startproc
@ %bb.0:
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.setfp	r7, sp, #12
	add	r7, sp, #12
	.cfi_def_cfa r7, 8
	.save	{r8, r9, r10, r11}
	push.w	{r8, r9, r10, r11}
	.cfi_offset r11, -24
	.cfi_offset r10, -28
	.cfi_offset r9, -32
	.cfi_offset r8, -36
	.pad	#4
	sub	sp, #4
	.vsave	{d8, d9, d10, d11, d12, d13, d14, d15}
	vpush	{d8, d9, d10, d11, d12, d13, d14, d15}
	.cfi_offset d15, -48
	.cfi_offset d14, -56
	.cfi_offset d13, -64
	.cfi_offset d12, -72
	.cfi_offset d11, -80
	.cfi_offset d10, -88
	.cfi_offset d9, -96
	.cfi_offset d8, -104
	.pad	#856
	sub.w	sp, sp, #856
	mov	r4, sp
	bfc	r4, #0, #4
	mov	sp, r4
	mov	r9, r1
	ldr	r1, [r7, #8]
	mov	r8, r3
	mov	r10, r2
	mov	lr, r0
.Ltmp230:
	.loc	1 898 7 prologue_end    @ ../crypto/hrss/hrss.c:898:7
	cmp	r1, #3
	beq.w	.LBB3_3
@ %bb.1:
	cmp	r1, #2
	bne.w	.LBB3_4
@ %bb.2:
	.loc	1 902 16                @ ../crypto/hrss/hrss.c:902:16
	vld1.16	{d20, d21}, [r10:128]!
	.loc	1 903 16                @ ../crypto/hrss/hrss.c:903:16
	add	r0, sp, #816
.Ltmp231:
	.loc	1 167 10                @ ../crypto/hrss/hrss.c:167:10
	vmov.i32	q8, #0x0
.Ltmp232:
	.loc	1 952 5                 @ ../crypto/hrss/hrss.c:952:5
	movs	r1, #30
	.loc	1 903 16                @ ../crypto/hrss/hrss.c:903:16
	vld1.64	{d22, d23}, [r10:128]
.Ltmp233:
	.loc	1 167 10                @ ../crypto/hrss/hrss.c:167:10
	vmov.i32	q9, #0x0
.Ltmp234:
	.loc	1 903 16                @ ../crypto/hrss/hrss.c:903:16
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp235:
	.loc	1 167 10                @ ../crypto/hrss/hrss.c:167:10
	add	r0, sp, #768
	vext.16	q13, q11, q8, #7
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #640
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
.Ltmp236:
	.loc	1 921 5                 @ ../crypto/hrss/hrss.c:921:5
	add.w	r0, r8, #2
.Ltmp237:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
.Ltmp238:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #784
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vmul.i16	q8, q8, q13
.Ltmp239:
	.loc	1 910 46 is_stmt 1      @ ../crypto/hrss/hrss.c:910:46
	add.w	r0, r8, #16
.Ltmp240:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vext.16	q4, q10, q11, #7
.Ltmp241:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp242:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	add	r0, sp, #736
.Ltmp243:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q12, q11
.Ltmp244:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp245:
	.loc	1 922 5                 @ ../crypto/hrss/hrss.c:922:5
	add.w	r0, r8, #18
.Ltmp246:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d22[], d23[]}, [r0:16]
.Ltmp247:
	.loc	1 167 10                @ ../crypto/hrss/hrss.c:167:10
	add	r0, sp, #832
.Ltmp248:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q11, q4
.Ltmp249:
	.loc	1 167 10                @ ../crypto/hrss/hrss.c:167:10
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
.Ltmp250:
	.loc	1 926 5                 @ ../crypto/hrss/hrss.c:926:5
	add.w	r0, r8, #4
.Ltmp251:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d22[], d23[]}, [r0:16]
.Ltmp252:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #752
.Ltmp253:
	.loc	1 167 10 is_stmt 1      @ ../crypto/hrss/hrss.c:167:10
	vext.16	q13, q4, q13, #7
.Ltmp254:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	vmla.i16	q8, q11, q13
.Ltmp255:
	.loc	1 927 5                 @ ../crypto/hrss/hrss.c:927:5
	add	r0, sp, #672
.Ltmp256:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vext.16	q11, q9, q10, #7
.Ltmp257:
	.loc	1 927 5                 @ ../crypto/hrss/hrss.c:927:5
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #20
.Ltmp258:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vext.16	q1, q11, q4, #7
.Ltmp259:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d6[], d7[]}, [r0:16]
.Ltmp260:
	.loc	1 931 5                 @ ../crypto/hrss/hrss.c:931:5
	add.w	r0, r8, #6
.Ltmp261:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q3, q1
.Ltmp262:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp263:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #704
.Ltmp264:
	.loc	1 167 10 is_stmt 1      @ ../crypto/hrss/hrss.c:167:10
	vext.16	q0, q1, q13, #7
.Ltmp265:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmul.i16	q13, q3, q13
.Ltmp266:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	vmla.i16	q8, q10, q0
.Ltmp267:
	.loc	1 932 5 is_stmt 1       @ ../crypto/hrss/hrss.c:932:5
	add	r0, sp, #624
.Ltmp268:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vext.16	q10, q9, q11, #7
	vorr	q12, q10, q10
.Ltmp269:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vext.16	q15, q10, q1, #7
.Ltmp270:
	.loc	1 932 5                 @ ../crypto/hrss/hrss.c:932:5
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #22
.Ltmp271:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d14[], d15[]}, [r0:16]
.Ltmp272:
	.loc	1 936 5                 @ ../crypto/hrss/hrss.c:936:5
	add.w	r0, r8, #8
.Ltmp273:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q7, q15
.Ltmp274:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp275:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #656
.Ltmp276:
	.loc	1 167 10 is_stmt 1      @ ../crypto/hrss/hrss.c:167:10
	vext.16	q11, q15, q0, #7
.Ltmp277:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vext.16	q2, q9, q12, #7
.Ltmp278:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q10, q11
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp279:
	.loc	1 937 5                 @ ../crypto/hrss/hrss.c:937:5
	add	r0, sp, #576
.Ltmp280:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vext.16	q10, q2, q15, #7
.Ltmp281:
	.loc	1 937 5                 @ ../crypto/hrss/hrss.c:937:5
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
	add.w	r0, r8, #24
.Ltmp282:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp283:
	.loc	1 941 5                 @ ../crypto/hrss/hrss.c:941:5
	add	r0, sp, #688
.Ltmp284:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q12, q10
.Ltmp285:
	.loc	1 167 10                @ ../crypto/hrss/hrss.c:167:10
	vext.16	q5, q10, q11, #7
.Ltmp286:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vext.16	q6, q9, q2, #7
.Ltmp287:
	.loc	1 941 5                 @ ../crypto/hrss/hrss.c:941:5
	vst1.64	{d10, d11}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #10
.Ltmp288:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d28[], d29[]}, [r0:16]
.Ltmp289:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #608
	vmla.i16	q8, q14, q5
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp290:
	.loc	1 942 5 is_stmt 1       @ ../crypto/hrss/hrss.c:942:5
	add.w	r0, r8, #26
.Ltmp291:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vext.16	q9, q6, q10, #7
.Ltmp292:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d28[], d29[]}, [r0:16]
.Ltmp293:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #592
	vmla.i16	q8, q14, q9
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #720
.Ltmp294:
	.loc	1 167 10 is_stmt 1      @ ../crypto/hrss/hrss.c:167:10
	vext.16	q14, q9, q5, #7
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp295:
	.loc	1 946 5                 @ ../crypto/hrss/hrss.c:946:5
	add.w	r0, r8, #12
.Ltmp296:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d4[], d5[]}, [r0:16]
.Ltmp297:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #800
	vmla.i16	q8, q2, q14
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
.Ltmp298:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #832
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #640
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp299:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #816
.Ltmp300:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q14, q2
.Ltmp301:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q7, q0
.Ltmp302:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q12, q11
.Ltmp303:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp304:
	.loc	1 159 59 is_stmt 1      @ ../crypto/hrss/hrss.c:159:59
	mov	r0, r8
.Ltmp305:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmul.i16	q0, q14, q11
.Ltmp306:
	.loc	1 159 59                @ ../crypto/hrss/hrss.c:159:59
	vld1.16	{d28[], d29[]}, [r0:16], r1
.Ltmp307:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r1, sp, #736
	vst1.64	{d28, d29}, [r1:128]    @ 16-byte Spill
	add	r1, sp, #768
	vld1.64	{d22, d23}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #784
	vmla.i16	q0, q14, q11
	vld1.64	{d10, d11}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #672
	vld1.64	{d22, d23}, [r1:128]    @ 16-byte Reload
.Ltmp308:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r1, sp, #832
.Ltmp309:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q5, q4
.Ltmp310:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d28, d29}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #752
	vld1.64	{d8, d9}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #624
	vld1.64	{d4, d5}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #704
	vmla.i16	q0, q14, q11
.Ltmp311:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q4, q1
	vld1.64	{d2, d3}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #576
.Ltmp312:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q3, q2
.Ltmp313:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q1, q15
	vld1.64	{d30, d31}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #656
.Ltmp314:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q7, q15
	vld1.64	{d14, d15}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #608
	vld1.64	{d6, d7}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #592
	vld1.64	{d28, d29}, [r1:128]    @ 16-byte Reload
.Ltmp315:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r1, sp, #800
.Ltmp316:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q7, q10
.Ltmp317:
	.loc	1 169 10 is_stmt 1      @ ../crypto/hrss/hrss.c:169:10
	vmov.i32	q10, #0x0
.Ltmp318:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q12, q6
.Ltmp319:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vext.16	q10, q10, q6, #7
.Ltmp320:
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vext.16	q12, q10, q9, #7
.Ltmp321:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q3, q9
.Ltmp322:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r1:128]    @ 16-byte Reload
.Ltmp323:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r1, sp, #816
.Ltmp324:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q14, q10
.Ltmp325:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q9, q12
.Ltmp326:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmul.i16	q9, q5, q11
	vld1.64	{d22, d23}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #736
	vld1.64	{d10, d11}, [r1:128]    @ 16-byte Reload
.Ltmp327:
	.loc	1 947 5 is_stmt 1       @ ../crypto/hrss/hrss.c:947:5
	add.w	r1, r8, #28
.Ltmp328:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q9, q5, q11
.Ltmp329:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d22[], d23[]}, [r1:16]
.Ltmp330:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r1, sp, #688
.Ltmp331:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q11, q12
.Ltmp332:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q9, q4, q2
.Ltmp333:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q9, q1, q15
.Ltmp334:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d30, d31}, [r1:128]    @ 16-byte Reload
.Ltmp335:
	.loc	1 951 5 is_stmt 1       @ ../crypto/hrss/hrss.c:951:5
	add.w	r1, r8, #14
.Ltmp336:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q14, q15
.Ltmp337:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vmov.i32	q14, #0x0
.Ltmp338:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q9, q7, q6
.Ltmp339:
	.loc	1 167 10                @ ../crypto/hrss/hrss.c:167:10
	vmov.i32	q1, #0x0
.Ltmp340:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q9, q3, q10
.Ltmp341:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vext.16	q10, q14, q10, #7
.Ltmp342:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d28[], d29[]}, [r1:16]
	add	r1, sp, #720
.Ltmp343:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q11, q10
	vld1.64	{d6, d7}, [r1:128]      @ 16-byte Reload
.Ltmp344:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r1, sp, #800
.Ltmp345:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q11, q3
.Ltmp346:
	.loc	1 167 10 is_stmt 1      @ ../crypto/hrss/hrss.c:167:10
	vext.16	q15, q12, q3, #7
	.loc	1 168 10                @ ../crypto/hrss/hrss.c:168:10
	vext.16	q11, q10, q12, #7
.Ltmp347:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q14, q15
.Ltmp348:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d24, d25}, [r1:128]    @ 16-byte Reload
.Ltmp349:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q14, q11
.Ltmp350:
	.loc	1 956 5 is_stmt 1       @ ../crypto/hrss/hrss.c:956:5
	mov	r1, lr
.Ltmp351:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q9, q12, q10
.Ltmp352:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp353:
	.loc	1 956 5 is_stmt 1       @ ../crypto/hrss/hrss.c:956:5
	movs	r0, #48
.Ltmp354:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q12, q15
.Ltmp355:
	.loc	1 169 10                @ ../crypto/hrss/hrss.c:169:10
	vext.16	q10, q1, q10, #7
.Ltmp356:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q12, q11
.Ltmp357:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q12, q10
.Ltmp358:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q9, q14, q10
.Ltmp359:
	.loc	1 956 5 is_stmt 1       @ ../crypto/hrss/hrss.c:956:5
	vst1.16	{d18, d19}, [r1:128], r0
	add.w	r0, lr, #32
	vst1.64	{d26, d27}, [r1:128]
	vst1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, #16
	vst1.64	{d0, d1}, [r0:128]
	b.w	.LBB3_17
.LBB3_3:
	.loc	1 0 5 is_stmt 0         @ ../crypto/hrss/hrss.c:0:5
	movs	r0, #32
	.loc	1 965 16 is_stmt 1      @ ../crypto/hrss/hrss.c:965:16
	add.w	r1, r10, #16
	.loc	1 964 16                @ ../crypto/hrss/hrss.c:964:16
	vld1.16	{d22, d23}, [r10:128], r0
.Ltmp360:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vmov.i32	q8, #0x0
.Ltmp361:
	.loc	1 966 16                @ ../crypto/hrss/hrss.c:966:16
	add	r0, sp, #752
.Ltmp362:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vmov.i32	q10, #0x0
.Ltmp363:
	.loc	1 965 16                @ ../crypto/hrss/hrss.c:965:16
	vld1.64	{d18, d19}, [r1:128]
.Ltmp364:
	.loc	1 159 59                @ ../crypto/hrss/hrss.c:159:59
	mov	r1, r8
	vorr	q14, q9, q9
.Ltmp365:
	.loc	1 966 16                @ ../crypto/hrss/hrss.c:966:16
	vld1.64	{d6, d7}, [r10:128]
.Ltmp366:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vext.16	q1, q3, q8, #7
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	vext.16	q15, q9, q3, #7
.Ltmp367:
	.loc	1 966 16                @ ../crypto/hrss/hrss.c:966:16
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
.Ltmp368:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vext.16	q8, q15, q1, #7
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
.Ltmp369:
	.loc	1 1000 5                @ ../crypto/hrss/hrss.c:1000:5
	add	r0, sp, #624
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #36
.Ltmp370:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp371:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #832
	vmul.i16	q2, q12, q8
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp372:
	.loc	1 994 5 is_stmt 1       @ ../crypto/hrss/hrss.c:994:5
	add.w	r0, r8, #34
.Ltmp373:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp374:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #256
	vmla.i16	q2, q12, q1
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #64
.Ltmp375:
	.loc	1 176 10 is_stmt 1      @ ../crypto/hrss/hrss.c:176:10
	vext.16	q13, q11, q9, #7
	vst1.64	{d2, d3}, [r0:128]      @ 16-byte Spill
.Ltmp376:
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	add	r0, sp, #704
	vext.16	q6, q13, q15, #7
	vorr	q15, q13, q13
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp377:
	.loc	1 1006 5                @ ../crypto/hrss/hrss.c:1006:5
	add.w	r0, r8, #38
.Ltmp378:
	.loc	1 177 10                @ ../crypto/hrss/hrss.c:177:10
	vext.16	q12, q10, q11, #7
.Ltmp379:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d18[], d19[]}, [r0:16]
.Ltmp380:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #320
.Ltmp381:
	.loc	1 174 10 is_stmt 1      @ ../crypto/hrss/hrss.c:174:10
	vext.16	q8, q6, q8, #7
.Ltmp382:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmla.i16	q2, q9, q8
.Ltmp383:
	.loc	1 176 10                @ ../crypto/hrss/hrss.c:176:10
	add	r0, sp, #160
	vext.16	q9, q12, q13, #7
	vorr	q7, q8, q8
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp384:
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	add	r0, sp, #672
	vorr	q4, q9, q9
	vext.16	q13, q9, q6, #7
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
.Ltmp385:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	add	r0, sp, #416
	vst1.64	{d12, d13}, [r0:128]    @ 16-byte Spill
.Ltmp386:
	.loc	1 1012 5                @ ../crypto/hrss/hrss.c:1012:5
	add	r0, sp, #48
	vst1.64	{d14, d15}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #40
.Ltmp387:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vext.16	q0, q13, q8, #7
.Ltmp388:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d22[], d23[]}, [r0:16]
	add	r0, sp, #352
	vorr	q8, q0, q0
.Ltmp389:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q2, q11, q0
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #544
.Ltmp390:
	.loc	1 177 10 is_stmt 1      @ ../crypto/hrss/hrss.c:177:10
	vext.16	q11, q10, q12, #7
.Ltmp391:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp392:
	.loc	1 176 10                @ ../crypto/hrss/hrss.c:176:10
	add	r0, sp, #736
	vext.16	q12, q11, q9, #7
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
.Ltmp393:
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	add	r0, sp, #640
	vorr	q5, q12, q12
	vext.16	q0, q12, q13, #7
	vst1.64	{d8, d9}, [r0:128]      @ 16-byte Spill
.Ltmp394:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	add	r0, sp, #272
.Ltmp395:
	.loc	1 177 10                @ ../crypto/hrss/hrss.c:177:10
	vext.16	q9, q10, q11, #7
.Ltmp396:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vst1.64	{d0, d1}, [r0:128]      @ 16-byte Spill
.Ltmp397:
	.loc	1 1018 5                @ ../crypto/hrss/hrss.c:1018:5
	add.w	r0, r8, #42
.Ltmp398:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vext.16	q13, q0, q8, #7
.Ltmp399:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #384
.Ltmp400:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q2, q8, q13
.Ltmp401:
	.loc	1 176 10 is_stmt 1      @ ../crypto/hrss/hrss.c:176:10
	vext.16	q11, q9, q12, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp402:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #496
.Ltmp403:
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	vext.16	q12, q11, q0, #7
.Ltmp404:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
.Ltmp405:
	.loc	1 176 10                @ ../crypto/hrss/hrss.c:176:10
	add	r0, sp, #720
	vorr	q0, q12, q12
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
.Ltmp406:
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	add	r0, sp, #656
.Ltmp407:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	vext.16	q12, q12, q13, #7
.Ltmp408:
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	vst1.64	{d10, d11}, [r0:128]    @ 16-byte Spill
.Ltmp409:
	.loc	1 1024 5                @ ../crypto/hrss/hrss.c:1024:5
	add	r0, sp, #464
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #44
.Ltmp410:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #400
.Ltmp411:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q2, q8, q12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp412:
	.loc	1 176 10 is_stmt 1      @ ../crypto/hrss/hrss.c:176:10
	add	r0, sp, #784
.Ltmp413:
	.loc	1 177 10                @ ../crypto/hrss/hrss.c:177:10
	vext.16	q8, q10, q9, #7
.Ltmp414:
	.loc	1 176 10                @ ../crypto/hrss/hrss.c:176:10
	vext.16	q9, q8, q11, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vorr	q8, q11, q11
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #592
.Ltmp415:
	.loc	1 175 10                @ ../crypto/hrss/hrss.c:175:10
	vext.16	q10, q9, q0, #7
	vorr	q9, q0, q0
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp416:
	.loc	1 1030 5                @ ../crypto/hrss/hrss.c:1030:5
	movs	r0, #46
.Ltmp417:
	.loc	1 159 59                @ ../crypto/hrss/hrss.c:159:59
	vld1.16	{d22[], d23[]}, [r1:16], r0
.Ltmp418:
	.loc	1 174 10                @ ../crypto/hrss/hrss.c:174:10
	add	r0, sp, #512
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #368
	vext.16	q11, q10, q12, #7
.Ltmp419:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r1:16]
.Ltmp420:
	.loc	1 1035 5                @ ../crypto/hrss/hrss.c:1035:5
	mov	r1, lr
.Ltmp421:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q2, q10, q11
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #176
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #144
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
.Ltmp422:
	.loc	1 980 5                 @ ../crypto/hrss/hrss.c:980:5
	add.w	r0, r8, #32
.Ltmp423:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp424:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #480
	vmul.i16	q13, q10, q14
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp425:
	.loc	1 979 5 is_stmt 1       @ ../crypto/hrss/hrss.c:979:5
	add.w	r0, r8, #16
	vorr	q14, q3, q3
.Ltmp426:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp427:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #688
	vmla.i16	q13, q10, q3
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp428:
	.loc	1 992 5 is_stmt 1       @ ../crypto/hrss/hrss.c:992:5
	add.w	r0, r8, #2
.Ltmp429:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp430:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #128
	vmla.i16	q13, q10, q1
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp431:
	.loc	1 993 5 is_stmt 1       @ ../crypto/hrss/hrss.c:993:5
	add.w	r0, r8, #18
.Ltmp432:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #288
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp433:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #768
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vmla.i16	q13, q10, q11
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp434:
	.loc	1 998 5 is_stmt 1       @ ../crypto/hrss/hrss.c:998:5
	add.w	r0, r8, #4
.Ltmp435:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp436:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #432
.Ltmp437:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q11, q15
.Ltmp438:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #624
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp439:
	.loc	1 999 5 is_stmt 1       @ ../crypto/hrss/hrss.c:999:5
	add.w	r0, r8, #20
.Ltmp440:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q12, q10
.Ltmp441:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp442:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #832
	vorr	q15, q10, q10
.Ltmp443:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q10, q6
.Ltmp444:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp445:
	.loc	1 1004 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1004:5
	add.w	r0, r8, #6
	vorr	q6, q14, q14
.Ltmp446:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q10, q4
.Ltmp447:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp448:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #608
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp449:
	.loc	1 1005 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1005:5
	add.w	r0, r8, #22
.Ltmp450:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q10, q7
.Ltmp451:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp452:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #240
	vorr	q7, q9, q9
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #320
	vmla.i16	q13, q10, q12
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp453:
	.loc	1 1010 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1010:5
	add.w	r0, r8, #8
.Ltmp454:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp455:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #96
.Ltmp456:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q2, q5
.Ltmp457:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #544
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp458:
	.loc	1 1011 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1011:5
	add.w	r0, r8, #24
.Ltmp459:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q12, q10
.Ltmp460:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #224
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #272
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
.Ltmp461:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q10, q5
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
.Ltmp462:
	.loc	1 1016 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1016:5
	add.w	r0, r8, #10
.Ltmp463:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q0, q8
.Ltmp464:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
.Ltmp465:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #576
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #496
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp466:
	.loc	1 1017 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1017:5
	add.w	r0, r8, #26
.Ltmp467:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q8, q10
.Ltmp468:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #208
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp469:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #16
	vmla.i16	q13, q8, q9
	vst1.64	{d14, d15}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #384
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
.Ltmp470:
	.loc	1 1022 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1022:5
	add.w	r0, r8, #12
.Ltmp471:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q4, q9
.Ltmp472:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
.Ltmp473:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #528
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #464
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp474:
	.loc	1 1023 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1023:5
	add.w	r0, r8, #28
.Ltmp475:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q8, q10
.Ltmp476:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #192
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp477:
	.loc	1 177 10 is_stmt 1      @ ../crypto/hrss/hrss.c:177:10
	add	r0, sp, #784
.Ltmp478:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q8, q3
.Ltmp479:
	.loc	1 177 10                @ ../crypto/hrss/hrss.c:177:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp480:
	.loc	1 176 10                @ ../crypto/hrss/hrss.c:176:10
	add	r0, sp, #336
.Ltmp481:
	.loc	1 177 10                @ ../crypto/hrss/hrss.c:177:10
	vmov.i32	q8, #0x0
	vext.16	q8, q8, q10, #7
.Ltmp482:
	.loc	1 176 10                @ ../crypto/hrss/hrss.c:176:10
	vext.16	q10, q8, q9, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #448
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #400
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp483:
	.loc	1 1028 5                @ ../crypto/hrss/hrss.c:1028:5
	add.w	r0, r8, #14
.Ltmp484:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q9, q10
.Ltmp485:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #80
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp486:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #368
.Ltmp487:
	.loc	1 175 10 is_stmt 1      @ ../crypto/hrss/hrss.c:175:10
	vext.16	q10, q10, q3, #7
.Ltmp488:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #560
	vmla.i16	q13, q8, q12
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp489:
	.loc	1 1029 5                @ ../crypto/hrss/hrss.c:1029:5
	add.w	r0, r8, #30
.Ltmp490:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.16	{d24[], d25[]}, [r0:16]
	add	r0, sp, #112
.Ltmp491:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q12, q10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #288
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp492:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #64
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #480
	vmul.i16	q8, q10, q8
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp493:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #768
.Ltmp494:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q14, q6
.Ltmp495:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp496:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #32
.Ltmp497:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q11, q14
	vorr	q11, q15, q15
.Ltmp498:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #624
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp499:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #416
.Ltmp500:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q15, q14
.Ltmp501:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #832
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
	vmla.i16	q8, q15, q14
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp502:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #48
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp503:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #816
.Ltmp504:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q14, q15
.Ltmp505:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #224
	vmla.i16	q8, q2, q15
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp506:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #544
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #208
	vmla.i16	q8, q15, q2
.Ltmp507:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q0, q5
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
.Ltmp508:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #496
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #192
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
.Ltmp509:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #464
.Ltmp510:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q0, q2
.Ltmp511:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp512:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #368
.Ltmp513:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q4, q7
.Ltmp514:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q1, q2
.Ltmp515:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q9, q3
.Ltmp516:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp517:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #704
.Ltmp518:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q8, q12, q9
.Ltmp519:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #688
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	vmul.i16	q12, q12, q9
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #752
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp520:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #480
.Ltmp521:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q5, q6
.Ltmp522:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #128
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
.Ltmp523:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #768
.Ltmp524:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q3
.Ltmp525:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp526:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #672
.Ltmp527:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q4, q9
.Ltmp528:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #160
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
.Ltmp529:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #256
.Ltmp530:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q10, q9
.Ltmp531:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #432
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp532:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #416
.Ltmp533:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q6
.Ltmp534:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp535:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #640
.Ltmp536:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q2, q9
.Ltmp537:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp538:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #832
.Ltmp539:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q11, q9
.Ltmp540:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp541:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #608
.Ltmp542:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q10
.Ltmp543:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #816
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp544:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #656
.Ltmp545:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q11
.Ltmp546:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #720
	vmla.i16	q12, q14, q9
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp547:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #320
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #96
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
.Ltmp548:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #272
.Ltmp549:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q14
.Ltmp550:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp551:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #592
.Ltmp552:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q7, q9
.Ltmp553:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp554:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #784
.Ltmp555:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q15, q9
.Ltmp556:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp557:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #576
.Ltmp558:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q11, q9
.Ltmp559:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #16
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp560:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #800
.Ltmp561:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q11
.Ltmp562:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #336
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp563:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #384
.Ltmp564:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q0, q9
.Ltmp565:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp566:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #528
.Ltmp567:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q11
.Ltmp568:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #304
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp569:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #448
.Ltmp570:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q15
.Ltmp571:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp572:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #400
.Ltmp573:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q1, q9
.Ltmp574:
	.loc	1 174 10 is_stmt 1      @ ../crypto/hrss/hrss.c:174:10
	vmov.i32	q9, #0x0
.Ltmp575:
	.loc	1 177 10                @ ../crypto/hrss/hrss.c:177:10
	vext.16	q1, q9, q11, #7
.Ltmp576:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #80
	vmla.i16	q12, q9, q1
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp577:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #560
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp578:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #688
.Ltmp579:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q11
.Ltmp580:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #704
	vmul.i16	q0, q11, q3
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp581:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #672
	vorr	q3, q4, q4
.Ltmp582:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q5, q11
.Ltmp583:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp584:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #288
	vorr	q5, q7, q7
.Ltmp585:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q4, q11
.Ltmp586:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp587:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #640
.Ltmp588:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q11, q6
.Ltmp589:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp590:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #32
.Ltmp591:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q2, q11
.Ltmp592:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #608
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp593:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #656
.Ltmp594:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q11, q10
.Ltmp595:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp596:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #240
.Ltmp597:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q2, q10
.Ltmp598:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp599:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #592
.Ltmp600:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q10, q14
.Ltmp601:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #784
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp602:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #224
.Ltmp603:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q7, q10
.Ltmp604:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #576
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
.Ltmp605:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #800
.Ltmp606:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q10, q15
.Ltmp607:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #336
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp608:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #208
.Ltmp609:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q7, q10
.Ltmp610:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #528
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #448
	vmla.i16	q0, q10, q11
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp611:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #192
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp612:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #752
.Ltmp613:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q4, q10
.Ltmp614:
	.loc	1 176 10 is_stmt 1      @ ../crypto/hrss/hrss.c:176:10
	vext.16	q10, q1, q10, #7
.Ltmp615:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q14, q1
.Ltmp616:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmul.i16	q14, q3, q6
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp617:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #432
.Ltmp618:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q9, q10
.Ltmp619:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q14, q3, q6
.Ltmp620:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
.Ltmp621:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #720
.Ltmp622:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q14, q3, q6
.Ltmp623:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #176
	vmla.i16	q14, q2, q3
.Ltmp624:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q14, q5, q15
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp625:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	add	r0, sp, #560
.Ltmp626:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q13, q15, q10
.Ltmp627:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q14, q7, q11
.Ltmp628:
	.loc	1 177 10 is_stmt 1      @ ../crypto/hrss/hrss.c:177:10
	vmov.i32	q11, #0x0
.Ltmp629:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q14, q4, q1
.Ltmp630:
	.loc	1 177 10                @ ../crypto/hrss/hrss.c:177:10
	vext.16	q11, q11, q1, #7
.Ltmp631:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #112
	vmla.i16	q8, q15, q1
.Ltmp632:
	.loc	1 162 10 is_stmt 0      @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q14, q9, q11
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp633:
	.loc	1 1035 5 is_stmt 1      @ ../crypto/hrss/hrss.c:1035:5
	movs	r0, #80
.Ltmp634:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q9, q10
.Ltmp635:
	.loc	1 1035 5                @ ../crypto/hrss/hrss.c:1035:5
	vst1.16	{d28, d29}, [r1:128], r0
	add	r0, sp, #144
.Ltmp636:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q0, q9, q11
.Ltmp637:
	.loc	1 1035 5                @ ../crypto/hrss/hrss.c:1035:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add.w	r0, lr, #64
	vst1.64	{d18, d19}, [r1:128]
.Ltmp638:
	.loc	1 162 10                @ ../crypto/hrss/hrss.c:162:10
	vmla.i16	q12, q15, q11
.Ltmp639:
	.loc	1 1035 5                @ ../crypto/hrss/hrss.c:1035:5
	vst1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, #16
	vst1.64	{d0, d1}, [r0:128]
	add.w	r0, lr, #48
	vst1.64	{d26, d27}, [r0:128]
	add.w	r0, lr, #32
	vst1.64	{d24, d25}, [r0:128]
	b	.LBB3_17
.LBB3_4:
	.loc	1 1045 28               @ ../crypto/hrss/hrss.c:1045:28
	lsr.w	r11, r1, #1
	.loc	1 1048 26               @ ../crypto/hrss/hrss.c:1048:26
	add.w	r0, r8, r11, lsl #4
	.loc	1 1047 26               @ ../crypto/hrss/hrss.c:1047:26
	str	r0, [sp, #816]          @ 4-byte Spill
	add.w	r0, r10, r11, lsl #4
	.loc	1 1046 29               @ ../crypto/hrss/hrss.c:1046:29
	str	r0, [sp, #800]          @ 4-byte Spill
	sub.w	r0, r1, r1, lsr #1
	str	r0, [sp, #832]          @ 4-byte Spill
	movs	r0, #0
	.loc	1 1052 3                @ ../crypto/hrss/hrss.c:1052:3
	cmp.w	r0, r1, lsr #1
	beq	.LBB3_7
@ %bb.5:
	.loc	1 1053 22               @ ../crypto/hrss/hrss.c:1053:22
	ldr	r0, [r7, #8]
	lsl.w	r1, r11, #4
	mov	r2, r11
	mov	r3, r8
	mov	r4, lr
	mov	r5, r10
	lsls	r0, r0, #4
	sub.w	r12, r0, r11, lsl #4
.LBB3_6:                                @ =>This Inner Loop Header: Depth=1
	adds	r0, r5, r1
	.loc	1 1053 33 is_stmt 0     @ ../crypto/hrss/hrss.c:1053:33
	vld1.16	{d16, d17}, [r5:128]!
	.loc	1 1054 33 is_stmt 1     @ ../crypto/hrss/hrss.c:1054:33
	adds	r6, r3, r1
	.loc	1 1052 24               @ ../crypto/hrss/hrss.c:1052:24
	subs	r2, #1
	.loc	1 1053 22               @ ../crypto/hrss/hrss.c:1053:22
	vld1.64	{d18, d19}, [r0:128]
	.loc	1 1054 23               @ ../crypto/hrss/hrss.c:1054:23
	add.w	r0, r4, r12
.Ltmp640:
	.loc	1 155 58                @ ../crypto/hrss/hrss.c:155:58
	vadd.i16	q8, q8, q9
.Ltmp641:
	.loc	1 1053 12               @ ../crypto/hrss/hrss.c:1053:12
	vst1.16	{d16, d17}, [r4:128]!
	.loc	1 1054 44               @ ../crypto/hrss/hrss.c:1054:44
	vld1.16	{d18, d19}, [r3:128]!
	.loc	1 1054 33 is_stmt 0     @ ../crypto/hrss/hrss.c:1054:33
	vld1.64	{d16, d17}, [r6:128]
.Ltmp642:
	.loc	1 155 58 is_stmt 1      @ ../crypto/hrss/hrss.c:155:58
	vadd.i16	q8, q9, q8
.Ltmp643:
	.loc	1 1054 23               @ ../crypto/hrss/hrss.c:1054:23
	vst1.64	{d16, d17}, [r0:128]
	.loc	1 1052 3                @ ../crypto/hrss/hrss.c:1052:3
	bne	.LBB3_6
.LBB3_7:
	.loc	1 1056 7                @ ../crypto/hrss/hrss.c:1056:7
	ldr	r0, [sp, #832]          @ 4-byte Reload
	ldr	r4, [r7, #8]
	cmp	r0, r11
	beq	.LBB3_9
@ %bb.8:
	.loc	1 1057 20               @ ../crypto/hrss/hrss.c:1057:20
	ldr	r0, [sp, #800]          @ 4-byte Reload
	add.w	r0, r0, r11, lsl #4
	vld1.64	{d16, d17}, [r0:128]
	.loc	1 1057 5 is_stmt 0      @ ../crypto/hrss/hrss.c:1057:5
	add.w	r0, lr, r11, lsl #4
	.loc	1 1057 18               @ ../crypto/hrss/hrss.c:1057:18
	vst1.64	{d16, d17}, [r0:128]
	.loc	1 1058 31 is_stmt 1     @ ../crypto/hrss/hrss.c:1058:31
	ldr	r0, [sp, #816]          @ 4-byte Reload
	add.w	r0, r0, r11, lsl #4
	vld1.64	{d16, d17}, [r0:128]
	.loc	1 1058 5 is_stmt 0      @ ../crypto/hrss/hrss.c:1058:5
	add.w	r0, lr, r4, lsl #4
	.loc	1 1058 29               @ ../crypto/hrss/hrss.c:1058:29
	vst1.64	{d16, d17}, [r0:128]
.LBB3_9:
	.loc	1 0 29                  @ ../crypto/hrss/hrss.c:0:29
	ldr	r4, [sp, #832]          @ 4-byte Reload
	mov	r6, r11
	.loc	1 1063 3 is_stmt 1      @ ../crypto/hrss/hrss.c:1063:3
	mov	r0, r9
	mov	r2, lr
	str	r4, [sp]
	mov	r5, lr
	.loc	1 1061 33               @ ../crypto/hrss/hrss.c:1061:33
	add.w	r11, r9, r4, lsl #5
	.loc	1 1063 50               @ ../crypto/hrss/hrss.c:1063:50
	add.w	r3, lr, r4, lsl #4
	.loc	1 1063 3 is_stmt 0      @ ../crypto/hrss/hrss.c:1063:3
	mov	r1, r11
	bl	poly_mul_vec_aux
	.loc	1 1065 33 is_stmt 1     @ ../crypto/hrss/hrss.c:1065:33
	ldr	r0, [r7, #8]
	.loc	1 1065 3 is_stmt 0      @ ../crypto/hrss/hrss.c:1065:3
	mov	r1, r11
	str	r4, [sp]
	.loc	1 1065 33               @ ../crypto/hrss/hrss.c:1065:33
	bic	r4, r0, #1
	.loc	1 1065 3                @ ../crypto/hrss/hrss.c:1065:3
	ldr	r2, [sp, #800]          @ 4-byte Reload
	ldr	r3, [sp, #816]          @ 4-byte Reload
	.loc	1 1065 21               @ ../crypto/hrss/hrss.c:1065:21
	add.w	r0, r5, r4, lsl #4
	.loc	1 1065 3                @ ../crypto/hrss/hrss.c:1065:3
	bl	poly_mul_vec_aux
	.loc	1 1067 3 is_stmt 1      @ ../crypto/hrss/hrss.c:1067:3
	mov	r1, r11
	mov	r0, r5
	mov	r2, r10
	mov	r3, r8
	str	r6, [sp]
	mov	r11, r6
	bl	poly_mul_vec_aux
	.loc	1 1070 3                @ ../crypto/hrss/hrss.c:1070:3
	cbz	r4, .LBB3_12
@ %bb.10:
	.loc	1 1071 26               @ ../crypto/hrss/hrss.c:1071:26
	lsl.w	r0, r11, #5
	mov	r1, r4
	mov	r2, r5
	mov	r3, r9
.LBB3_11:                               @ =>This Inner Loop Header: Depth=1
	.loc	1 1071 54 is_stmt 0     @ ../crypto/hrss/hrss.c:1071:54
	adds	r6, r2, r0
	.loc	1 1071 46               @ ../crypto/hrss/hrss.c:1071:46
	vld1.16	{d16, d17}, [r2:128]!
	.loc	1 1070 24 is_stmt 1     @ ../crypto/hrss/hrss.c:1070:24
	subs	r1, #1
	.loc	1 1071 26               @ ../crypto/hrss/hrss.c:1071:26
	vld1.64	{d18, d19}, [r3:128]
.Ltmp644:
	.loc	1 155 58                @ ../crypto/hrss/hrss.c:155:58
	vsub.i16	q8, q9, q8
.Ltmp645:
	.loc	1 1071 54               @ ../crypto/hrss/hrss.c:1071:54
	vld1.64	{d20, d21}, [r6:128]
.Ltmp646:
	.loc	1 157 58                @ ../crypto/hrss/hrss.c:157:58
	vsub.i16	q8, q8, q10
.Ltmp647:
	.loc	1 1071 16               @ ../crypto/hrss/hrss.c:1071:16
	vst1.16	{d16, d17}, [r3:128]!
	.loc	1 1070 3                @ ../crypto/hrss/hrss.c:1070:3
	bne	.LBB3_11
.LBB3_12:
	.loc	1 0 3 is_stmt 0         @ ../crypto/hrss/hrss.c:0:3
	ldr	r1, [sp, #832]          @ 4-byte Reload
	.loc	1 1073 7 is_stmt 1      @ ../crypto/hrss/hrss.c:1073:7
	cmp	r1, r11
	lsl.w	r0, r1, #1
	beq	.LBB3_14
@ %bb.13:
	.loc	1 1074 58               @ ../crypto/hrss/hrss.c:1074:58
	add.w	r1, r5, r11, lsl #6
	vld1.64	{d16, d17}, [r1:128]
	.loc	1 1074 36 is_stmt 0     @ ../crypto/hrss/hrss.c:1074:36
	add.w	r1, r9, r4, lsl #4
	vld1.64	{d18, d19}, [r1:128]
.Ltmp648:
	.loc	1 157 58 is_stmt 1      @ ../crypto/hrss/hrss.c:157:58
	vsub.i16	q8, q9, q8
.Ltmp649:
	.loc	1 1074 26               @ ../crypto/hrss/hrss.c:1074:26
	vst1.64	{d16, d17}, [r1:128]
	movs	r1, #16
	.loc	1 1076 43               @ ../crypto/hrss/hrss.c:1076:43
	orr.w	r1, r1, r11, lsl #6
	add	r1, r5
	vld1.64	{d16, d17}, [r1:128]
	.loc	1 1076 17 is_stmt 0     @ ../crypto/hrss/hrss.c:1076:17
	ldr	r1, [r7, #8]
	orr	r1, r1, #1
	add.w	r1, r9, r1, lsl #4
	vld1.64	{d18, d19}, [r1:128]
.Ltmp650:
	.loc	1 157 58 is_stmt 1      @ ../crypto/hrss/hrss.c:157:58
	vsub.i16	q8, q9, q8
.Ltmp651:
	.loc	1 1075 30               @ ../crypto/hrss/hrss.c:1075:30
	vst1.64	{d16, d17}, [r1:128]
.LBB3_14:
	.loc	1 1080 3                @ ../crypto/hrss/hrss.c:1080:3
	cbz	r0, .LBB3_17
@ %bb.15:
	.loc	1 1081 44               @ ../crypto/hrss/hrss.c:1081:44
	add.w	r1, r5, r11, lsl #4
.LBB3_16:                               @ =>This Inner Loop Header: Depth=1
	.loc	1 1081 32 is_stmt 0     @ ../crypto/hrss/hrss.c:1081:32
	vld1.64	{d16, d17}, [r1:128]
	.loc	1 1080 24 is_stmt 1     @ ../crypto/hrss/hrss.c:1080:24
	subs	r0, #1
	.loc	1 1081 50               @ ../crypto/hrss/hrss.c:1081:50
	vld1.16	{d18, d19}, [r9:128]!
.Ltmp652:
	.loc	1 155 58                @ ../crypto/hrss/hrss.c:155:58
	vadd.i16	q8, q9, q8
.Ltmp653:
	.loc	1 1081 22               @ ../crypto/hrss/hrss.c:1081:22
	vst1.16	{d16, d17}, [r1:128]!
	.loc	1 1080 3                @ ../crypto/hrss/hrss.c:1080:3
	bne	.LBB3_16
.LBB3_17:
	.loc	1 1083 1                @ ../crypto/hrss/hrss.c:1083:1
	sub.w	r4, r7, #96
	mov	sp, r4
	vpop	{d8, d9, d10, d11, d12, d13, d14, d15}
	add	sp, #4
	pop.w	{r8, r9, r10, r11}
	pop	{r4, r5, r6, r7, pc}
.Ltmp654:
.Lfunc_end3:
	.size	poly_mul_vec_aux, .Lfunc_end3-poly_mul_vec_aux
	.cfi_endproc
	.fnend

	.section	".note.GNU-stack","",%progbits
	.section	.debug_line,"",%progbits

#endif
