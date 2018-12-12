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

	.section	.text.poly3_invert_vec,"ax",%progbits
	.hidden	poly3_invert_vec        @ -- Begin function poly3_invert_vec
	.globl	poly3_invert_vec
	.p2align	4
	.type	poly3_invert_vec,%function
	.code	16                      @ @poly3_invert_vec
	.thumb_func
poly3_invert_vec:
.Lfunc_begin0:
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
	movs	r0, #104
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
	add.w	lr, sp, #672
	vmov.i32	q11, #0x0
	mov.w	r6, #700
	vld1.64	{d16, d17}, [r0:128]
	add.w	r0, r1, #152
	vmov.i32	q12, #0x0
	vst1.64	{d16, d17}, [lr:128]    @ 16-byte Spill
	add.w	lr, sp, #384
	vld1.32	{d16, d17}, [r2]
	add.w	r2, r1, #64
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
	add.w	lr, sp, #544
	vld1.32	{d20, d21}, [r2]
	add.w	r2, r1, #32
	vld1.32	{d30, d31}, [r0]
	add.w	r0, r1, #16
	vldr	d18, [r1, #80]
	vldr	d16, [r1, #168]
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
	add	r0, sp, #768
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	b	.LBB0_3
	.p2align	4
@ %bb.1:
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
	add	r0, sp, #96
	vand	q9, q1, q15
	vand	q13, q8, q15
.Ltmp1:
	subs	r4, r5, r6
.Ltmp2:
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #128
	vand	q11, q8, q2
.Ltmp3:
	eor.w	r3, r5, r6
.Ltmp4:
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	vand	q12, q1, q2
	veor	q9, q11, q9
.Ltmp5:
	eors	r4, r5
.Ltmp6:
	veor	q11, q13, q12
.Ltmp7:
	orrs	r4, r3
.Ltmp8:
	vand	q12, q14, q9
.Ltmp9:
	eors	r4, r5
.Ltmp10:
	vand	q9, q14, q11
	add	r0, sp, #912
.Ltmp11:
	asrs	r4, r4, #31
.Ltmp12:
	subs	r2, #1
.Ltmp13:
	vorr	q11, q9, q12
.Ltmp14:
	vmov.16	d26[0], r4
.Ltmp15:
	vshl.i16	q9, q9, #15
.Ltmp16:
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp17:
	add	r0, sp, #192
.Ltmp18:
	vshl.i16	q11, q11, #15
.Ltmp19:
	vshr.s16	q11, q11, #15
	vand	q11, q13, q11
.Ltmp20:
	veor	q13, q8, q15
.Ltmp21:
	vdup.16	q0, d22[0]
.Ltmp22:
	veor	q11, q1, q2
	vand	q13, q0, q13
	vand	q14, q0, q11
	veor	q8, q13, q8
	veor	q1, q14, q1
.Ltmp23:
	vshl.i16	q11, q12, #15
.Ltmp24:
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp25:
	add	r0, sp, #160
	vst1.64	{d2, d3}, [r0:128]      @ 16-byte Spill
	add	r0, sp, #608
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp26:
	add	r0, sp, #144
.Ltmp27:
	vshl.s16	q9, q9, q3
.Ltmp28:
	vshl.s16	q11, q11, q3
.Ltmp29:
	vdup.16	q9, d18[0]
.Ltmp30:
	vdup.16	q3, d22[0]
.Ltmp31:
	vand	q12, q8, q9
	vand	q11, q1, q3
	veor	q5, q12, q11
	vand	q12, q1, q9
	vand	q1, q8, q3
	veor	q4, q1, q12
.Ltmp32:
	veor	q1, q14, q2
	veor	q14, q13, q15
.Ltmp33:
	vand	q2, q5, q1
	vorr	q8, q14, q1
	vbic	q13, q4, q8
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vorr	q8, q5, q4
	add	r0, sp, #80
	veor	q13, q13, q2
	vbic	q2, q14, q8
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #384
	veor	q6, q13, q2
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
.Ltmp34:
	add	r0, sp, #928
	veor	q13, q10, q12
	vst1.64	{d0, d1}, [r0:128]      @ 16-byte Spill
	add	r0, sp, #176
	vand	q13, q0, q13
.Ltmp35:
	vand	q14, q4, q14
.Ltmp36:
	veor	q10, q13, q10
.Ltmp37:
	vand	q15, q10, q9
.Ltmp38:
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #528
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp39:
	add	r0, sp, #16
.Ltmp40:
	veor	q2, q8, q11
.Ltmp41:
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #528
.Ltmp42:
	vand	q2, q0, q2
	veor	q8, q2, q8
.Ltmp43:
	vand	q7, q8, q3
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp44:
	add	r0, sp, #32
.Ltmp45:
	veor	q15, q15, q7
	vand	q7, q8, q9
	vand	q8, q10, q3
.Ltmp46:
	veor	q10, q13, q12
.Ltmp47:
	veor	q9, q8, q7
.Ltmp48:
	veor	q7, q2, q11
.Ltmp49:
	vorr	q12, q15, q9
	vorr	q0, q10, q7
	vand	q2, q15, q7
	vbic	q13, q9, q0
.Ltmp50:
	vshr.u16	q11, q6, #1
.Ltmp51:
	veor	q13, q13, q2
	vbic	q2, q10, q12
	veor	q8, q13, q2
	vmov.i32	q2, #0x0
.Ltmp52:
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q8, #15
	add	r0, sp, #384
	vext.16	q13, q2, q8, #1
	vorr	q11, q13, q11
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q13, q6, #15
.Ltmp53:
	add	r0, sp, #80
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #144
.Ltmp54:
	vext.16	q13, q13, q2, #1
	vorr	q6, q11, q13
.Ltmp55:
	vbic	q11, q1, q8
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	vbic	q13, q5, q8
.Ltmp56:
	add	r0, sp, #352
.Ltmp57:
	vand	q8, q9, q10
	veor	q13, q13, q14
	veor	q11, q13, q11
	vbic	q13, q7, q12
	vbic	q12, q15, q0
	veor	q8, q12, q8
	veor	q1, q8, q13
.Ltmp58:
	vshr.u16	q8, q11, #1
	vshl.i16	q9, q1, #15
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #80
	vext.16	q9, q2, q9, #1
	vorr	q8, q9, q8
	vshl.i16	q9, q11, #15
	vext.16	q9, q9, q2, #1
	vorr	q12, q8, q9
.Ltmp59:
	vorr	q8, q12, q6
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #112
	vst1.64	{d12, d13}, [r0:128]    @ 16-byte Spill
.Ltmp60:
	add	r0, sp, #608
	vshl.i16	q8, q8, #15
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #144
	vshl.s16	q8, q8, q9
	vdup.16	q11, d16[0]
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #896
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp61:
	add	r0, sp, #912
	veor	q8, q6, q10
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #896
	vand	q9, q11, q9
	vand	q8, q9, q8
	veor	q10, q8, q10
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #880
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #880
	veor	q8, q12, q10
	vand	q8, q9, q8
	veor	q10, q8, q10
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #672
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #656
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #928
.Ltmp62:
	veor	q8, q12, q13
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #624
	vand	q8, q14, q8
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #448
	veor	q12, q8, q12
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #16
	veor	q9, q4, q15
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #448
	vand	q9, q14, q9
.Ltmp63:
	vand	q11, q12, q0
.Ltmp64:
	veor	q4, q9, q4
	veor	q9, q9, q15
.Ltmp65:
	vand	q10, q4, q3
	vst1.64	{d8, d9}, [r0:128]      @ 16-byte Spill
	add	r0, sp, #672
	veor	q10, q11, q10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp66:
	veor	q8, q8, q13
.Ltmp67:
	vand	q11, q4, q0
.Ltmp68:
	add	r0, sp, #64
.Ltmp69:
	vand	q12, q12, q3
	vorr	q13, q8, q9
	veor	q11, q12, q11
	vand	q15, q10, q9
	vbic	q12, q11, q13
	veor	q12, q12, q15
	vorr	q15, q10, q11
	vbic	q10, q10, q13
	vbic	q4, q8, q15
	vand	q8, q11, q8
	veor	q12, q12, q4
	vbic	q9, q9, q15
	veor	q8, q10, q8
.Ltmp70:
	vshr.u16	q4, q12, #1
	vshl.i16	q12, q12, #15
.Ltmp71:
	veor	q8, q8, q9
	vmov.i32	q11, #0x0
.Ltmp72:
	vext.16	q5, q12, q2, #1
	vshr.u16	q9, q8, #1
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	vorr	q12, q5, q4
.Ltmp73:
	add	r0, sp, #656
.Ltmp74:
	vshl.i16	q8, q8, #15
.Ltmp75:
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp76:
	add	r0, sp, #48
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #624
	vext.16	q8, q8, q2, #1
	vorr	q8, q8, q9
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
	veor	q9, q12, q4
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #400
	vand	q9, q14, q9
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	veor	q10, q2, q5
	veor	q12, q9, q12
	vand	q10, q14, q10
.Ltmp78:
	vand	q15, q12, q0
.Ltmp79:
	veor	q2, q10, q2
	veor	q10, q10, q5
.Ltmp80:
	vand	q13, q2, q3
.Ltmp81:
	veor	q9, q9, q4
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
.Ltmp82:
	veor	q13, q15, q13
	add	r0, sp, #592
	vand	q15, q2, q0
	vand	q2, q12, q3
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	vorr	q4, q9, q10
.Ltmp83:
	add	r0, sp, #384
.Ltmp84:
	veor	q15, q2, q15
.Ltmp85:
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
.Ltmp86:
	vand	q5, q13, q10
.Ltmp87:
	add	r0, sp, #384
.Ltmp88:
	vbic	q2, q15, q4
	veor	q2, q2, q5
	vorr	q5, q13, q15
	vbic	q13, q13, q4
	vbic	q6, q9, q5
	vand	q9, q15, q9
	veor	q6, q2, q6
	vbic	q10, q10, q5
	veor	q9, q13, q9
.Ltmp89:
	vshl.i16	q2, q6, #15
	vext.16	q7, q11, q2, #1
	vorr	q8, q7, q8
	vext.16	q7, q12, q11, #1
	vorr	q8, q8, q7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshr.u16	q8, q1, #1
.Ltmp90:
	veor	q1, q9, q10
.Ltmp91:
	add	r0, sp, #352
	vshl.i16	q13, q1, #15
	vext.16	q9, q11, q13, #1
	vorr	q8, q9, q8
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
	vext.16	q9, q9, q11, #1
	vmov.i32	q11, #0x0
	vorr	q8, q8, q9
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #576
	vshr.u16	q8, q6, #1
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #496
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #480
.Ltmp92:
	veor	q9, q12, q5
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #416
	vand	q9, q14, q9
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #480
	veor	q10, q4, q6
	veor	q12, q9, q12
	vand	q10, q14, q10
.Ltmp93:
	vand	q15, q12, q0
.Ltmp94:
	veor	q4, q10, q4
	veor	q10, q10, q6
.Ltmp95:
	vand	q14, q4, q3
.Ltmp96:
	veor	q9, q9, q5
	vst1.64	{d8, d9}, [r0:128]      @ 16-byte Spill
.Ltmp97:
	veor	q15, q15, q14
	add	r0, sp, #576
	vand	q14, q4, q0
	vand	q4, q12, q3
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	vorr	q5, q9, q10
.Ltmp98:
	add	r0, sp, #432
.Ltmp99:
	veor	q4, q4, q14
	vand	q6, q15, q10
	vbic	q14, q4, q5
	veor	q14, q14, q6
	vorr	q6, q15, q4
	vbic	q7, q9, q6
	vand	q9, q4, q9
	veor	q7, q14, q7
	vbic	q10, q10, q6
.Ltmp100:
	vshl.i16	q14, q7, #15
	vext.16	q12, q11, q14, #1
	vorr	q8, q12, q8
	vext.16	q12, q2, q11, #1
	vorr	q8, q8, q12
	vext.16	q14, q14, q11, #1
.Ltmp101:
	vbic	q12, q15, q5
	veor	q9, q12, q9
.Ltmp102:
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshr.u16	q8, q1, #1
	add	r0, sp, #400
.Ltmp103:
	veor	q2, q9, q10
.Ltmp104:
	vshl.i16	q1, q2, #15
	vext.16	q9, q11, q1, #1
	vorr	q8, q9, q8
	vext.16	q9, q13, q11, #1
	vorr	q8, q8, q9
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #640
	vshr.u16	q8, q7, #1
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #560
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #928
.Ltmp105:
	veor	q9, q15, q4
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #544
	vand	q9, q12, q9
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #464
	veor	q15, q9, q15
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #464
	veor	q10, q6, q5
.Ltmp106:
	vand	q13, q15, q0
.Ltmp107:
	vand	q10, q12, q10
	veor	q9, q9, q4
	veor	q6, q10, q6
	veor	q10, q10, q5
.Ltmp108:
	vand	q12, q6, q3
	vst1.64	{d12, d13}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #560
	veor	q12, q13, q12
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	vand	q13, q6, q0
	vand	q15, q15, q3
.Ltmp109:
	add	r0, sp, #496
.Ltmp110:
	vand	q5, q12, q10
	veor	q13, q15, q13
	vorr	q15, q9, q10
	vbic	q4, q13, q15
	veor	q4, q4, q5
	vorr	q5, q12, q13
	vbic	q12, q12, q15
	vbic	q6, q9, q5
	vand	q9, q13, q9
	veor	q4, q4, q6
	vbic	q10, q10, q5
	veor	q9, q12, q9
.Ltmp111:
	vshl.i16	q6, q4, #15
.Ltmp112:
	veor	q9, q9, q10
	vmov.i32	q13, #0x0
.Ltmp113:
	vext.16	q7, q11, q6, #1
	vmov.i32	q11, #0x0
	vshl.i16	q10, q9, #15
	vorr	q8, q7, q8
	vshr.u16	q9, q9, #1
	vorr	q8, q8, q14
	vext.16	q12, q13, q10, #1
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshr.u16	q8, q2, #1
	add	r0, sp, #416
	vorr	q8, q12, q8
	vext.16	q12, q1, q13, #1
	vorr	q8, q8, q12
	vshr.u16	q12, q4, #1
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #64
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #640
	vext.16	q8, q13, q8, #1
	vorr	q8, q8, q12
	vext.16	q12, q6, q13, #1
	vorr	q8, q8, q12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #48
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
.Ltmp114:
	add	r0, sp, #544
.Ltmp115:
	vext.16	q8, q13, q8, #1
	vorr	q8, q8, q9
	vext.16	q9, q10, q11, #1
	vorr	q8, q8, q9
.Ltmp116:
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #864
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #928
	veor	q8, q9, q13
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vand	q8, q7, q8
.Ltmp117:
	vmov.32	r4, d14[0]
.Ltmp118:
	veor	q15, q8, q9
	veor	q8, q8, q13
.Ltmp119:
	vand	q11, q15, q0
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
.Ltmp120:
	veor	q9, q10, q14
	vand	q9, q7, q9
	veor	q12, q9, q10
	veor	q9, q9, q14
.Ltmp121:
	vand	q10, q12, q3
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #864
	veor	q10, q11, q10
	vand	q11, q12, q0
	vand	q12, q15, q3
.Ltmp122:
	and.w	r3, r3, r4
.Ltmp123:
	vand	q14, q10, q9
.Ltmp124:
	eor.w	r5, r5, r3
.Ltmp125:
	veor	q11, q12, q11
.Ltmp126:
	add.w	r4, r5, r12
.Ltmp127:
	vorr	q12, q8, q9
.Ltmp128:
	eor.w	r6, r6, r3
.Ltmp129:
	vbic	q13, q11, q12
	veor	q13, q13, q14
	vorr	q14, q10, q11
	vbic	q10, q10, q12
	vbic	q15, q8, q14
	vand	q8, q11, q8
	veor	q13, q13, q15
	vbic	q9, q9, q14
	veor	q8, q10, q8
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
	veor	q8, q8, q9
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #848
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #288
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #288
.Ltmp130:
	veor	q8, q10, q14
	vand	q9, q7, q8
	veor	q13, q9, q10
	veor	q9, q9, q14
.Ltmp131:
	vand	q12, q13, q0
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #784
	vand	q13, q13, q3
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #272
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #272
.Ltmp132:
	veor	q8, q11, q15
	vand	q10, q7, q8
	veor	q8, q10, q11
	veor	q10, q10, q15
.Ltmp133:
	vand	q11, q8, q3
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #848
	veor	q11, q12, q11
	vand	q12, q8, q0
	vand	q15, q11, q10
	veor	q12, q13, q12
	vorr	q13, q9, q10
	vbic	q14, q12, q13
	veor	q14, q14, q15
	vorr	q15, q11, q12
	vbic	q11, q11, q13
	vbic	q4, q9, q15
	vand	q9, q12, q9
	veor	q8, q14, q4
	vbic	q10, q10, q15
	veor	q9, q11, q9
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #784
	veor	q8, q9, q10
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #832
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #320
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #752
.Ltmp134:
	veor	q9, q10, q8
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #304
	vand	q9, q7, q9
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp135:
	add	r0, sp, #304
.Ltmp136:
	veor	q12, q9, q10
	veor	q10, q11, q15
.Ltmp137:
	vand	q13, q12, q0
.Ltmp138:
	vand	q10, q7, q10
	veor	q9, q9, q8
	veor	q14, q10, q11
	veor	q10, q10, q15
.Ltmp139:
	vand	q11, q14, q3
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #832
	veor	q11, q13, q11
	vand	q13, q14, q0
	vand	q14, q12, q3
	vand	q4, q11, q10
	veor	q13, q14, q13
	vorr	q14, q9, q10
	vbic	q15, q13, q14
	veor	q15, q15, q4
	vorr	q4, q11, q13
	vbic	q11, q11, q14
	vbic	q5, q9, q4
	vand	q9, q13, q9
	veor	q8, q15, q5
	vbic	q10, q10, q4
	veor	q9, q11, q9
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #752
	veor	q8, q9, q10
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #224
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
.Ltmp140:
	veor	q9, q10, q8
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #336
	vand	q9, q7, q9
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp141:
	add	r0, sp, #816
.Ltmp142:
	veor	q14, q9, q10
	veor	q10, q11, q1
.Ltmp143:
	vand	q15, q14, q0
.Ltmp144:
	vand	q10, q7, q10
.Ltmp145:
	vand	q4, q14, q3
.Ltmp146:
	veor	q11, q10, q11
	veor	q10, q10, q1
.Ltmp147:
	vand	q13, q11, q3
.Ltmp148:
	veor	q9, q9, q8
.Ltmp149:
	veor	q13, q15, q13
	vand	q15, q11, q0
	vand	q1, q13, q10
	veor	q15, q4, q15
	vorr	q4, q9, q10
	vbic	q5, q15, q4
	veor	q1, q5, q1
	vorr	q5, q13, q15
	vbic	q13, q13, q4
	vbic	q2, q9, q5
	vand	q9, q15, q9
	veor	q8, q1, q2
	vbic	q10, q10, q5
	veor	q9, q13, q9
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #736
	veor	q8, q9, q10
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #96
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #720
.Ltmp150:
	veor	q9, q10, q8
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #128
	vand	q9, q7, q9
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
.Ltmp151:
	add	r0, sp, #800
.Ltmp152:
	veor	q4, q9, q10
	veor	q10, q13, q5
.Ltmp153:
	vand	q1, q4, q0
.Ltmp154:
	vand	q10, q7, q10
.Ltmp155:
	vand	q2, q4, q3
.Ltmp156:
	veor	q13, q10, q13
	veor	q10, q10, q5
.Ltmp157:
	vand	q15, q13, q3
.Ltmp158:
	veor	q9, q9, q8
.Ltmp159:
	veor	q15, q1, q15
	vand	q1, q13, q0
	vand	q8, q15, q10
	veor	q1, q2, q1
	vorr	q2, q9, q10
	vbic	q5, q1, q2
	veor	q8, q5, q8
	vorr	q5, q15, q1
	vbic	q6, q9, q5
	vand	q9, q1, q9
	veor	q8, q8, q6
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vbic	q8, q10, q5
	vbic	q10, q15, q2
.Ltmp160:
	add	r0, sp, #720
.Ltmp161:
	veor	q9, q10, q9
	veor	q8, q9, q8
.Ltmp162:
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #704
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #208
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #368
	veor	q8, q9, q5
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #688
	vand	q8, q7, q8
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
.Ltmp163:
	add	r0, sp, #704
.Ltmp164:
	veor	q10, q15, q6
	veor	q9, q8, q9
	vand	q10, q7, q10
.Ltmp165:
	vand	q2, q9, q0
.Ltmp166:
	veor	q15, q10, q15
	veor	q10, q10, q6
.Ltmp167:
	vand	q1, q15, q3
.Ltmp168:
	veor	q8, q8, q5
.Ltmp169:
	veor	q1, q2, q1
	vand	q2, q15, q0
	vand	q0, q9, q3
	vand	q5, q1, q10
	veor	q0, q0, q2
	vorr	q2, q8, q10
	vbic	q3, q0, q2
	veor	q3, q3, q5
	vorr	q5, q1, q0
	vbic	q1, q1, q2
	vbic	q6, q8, q5
	vand	q8, q0, q8
	veor	q3, q3, q6
	vbic	q10, q10, q5
	veor	q8, q1, q8
	vst1.64	{d6, d7}, [r0:128]      @ 16-byte Spill
.Ltmp170:
	vshr.u16	q0, q9, #15
.Ltmp171:
	veor	q8, q8, q10
.Ltmp172:
	add	r0, sp, #688
	vmov.i32	q3, #0x0
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q9, #1
	add	r0, sp, #208
	vext.16	q9, q3, q0, #7
	vorr	q8, q9, q8
	vshr.u16	q9, q15, #15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q15, #1
	add	r0, sp, #368
	vext.16	q10, q3, q9, #7
	vorr	q8, q10, q8
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #288
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vshr.u16	q8, q5, #15
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #256
	vshl.i16	q10, q1, #1
	vext.16	q15, q8, q3, #7
	vorr	q10, q15, q10
	vext.16	q8, q3, q8, #7
	vshr.u16	q15, q1, #15
	vext.16	q15, q3, q15, #7
	vorr	q10, q10, q15
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #272
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
	vshr.u16	q10, q6, #15
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #240
	vshl.i16	q15, q2, #1
	vext.16	q1, q10, q3, #7
	vorr	q15, q1, q15
	vext.16	q10, q3, q10, #7
	vshr.u16	q1, q2, #15
	vext.16	q1, q3, q1, #7
	vorr	q15, q15, q1
	vshr.u16	q1, q12, #15
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	vshl.i16	q15, q5, #1
	add	r0, sp, #288
	vext.16	q2, q1, q3, #7
	vorr	q15, q2, q15
	vorr	q8, q15, q8
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vshl.i16	q8, q6, #1
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #80
	vshr.u16	q15, q5, #15
	vext.16	q2, q15, q3, #7
	vorr	q8, q2, q8
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #272
	vorr	q8, q8, q10
	vext.16	q15, q3, q15, #7
	vshr.u16	q10, q14, #15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q12, #1
	add	r0, sp, #320
	vext.16	q12, q10, q3, #7
	vorr	q8, q12, q8
	vext.16	q12, q3, q1, #7
	vorr	q8, q8, q12
	vext.16	q10, q3, q10, #7
	vshr.u16	q12, q11, #15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q5, #1
	add	r0, sp, #160
	vext.16	q1, q12, q3, #7
	vorr	q8, q1, q8
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #304
	vorr	q8, q8, q15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q14, #1
	vshr.u16	q14, q4, #15
	add	r0, sp, #112
	vext.16	q15, q14, q3, #7
	vorr	q8, q15, q8
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #224
	vorr	q8, q8, q10
	vshr.u16	q10, q13, #15
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vshl.i16	q8, q11, #1
	add	r0, sp, #336
	vext.16	q11, q10, q3, #7
	vorr	q8, q11, q8
	vext.16	q11, q3, q12, #7
	vmov.i32	q12, #0x0
	vorr	q8, q8, q11
	vshl.i16	q11, q4, #1
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #176
	vext.16	q8, q0, q3, #7
	vorr	q8, q8, q11
	vext.16	q11, q3, q14, #7
	vorr	q11, q8, q11
	vext.16	q8, q9, q3, #7
	vshl.i16	q9, q13, #1
	vorr	q8, q8, q9
	vext.16	q9, q12, q10, #7
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp173:
	sub.w	r0, r5, #2
	and.w	r0, r0, r4
.Ltmp174:
	vorr	q12, q8, q9
.Ltmp175:
	sub.w	r5, r5, #1
.Ltmp176:
	asr.w	r0, r0, #31
.Ltmp177:
	vdup.16	q8, r0
	add	r0, sp, #192
.Ltmp178:
	vmvn	q9, q8
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
.Ltmp179:
	add	r0, sp, #912
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
.Ltmp180:
	add	r0, sp, #144
	vorr	q14, q9, q9
.Ltmp181:
	vmov.32	r4, d26[0]
.Ltmp182:
	vld1.64	{d26, d27}, [r0:128]    @ 16-byte Reload
	vmov.32	r0, d26[0]
.Ltmp183:
	and.w	r0, r0, r4
	and	r4, r4, #1
	add	r1, r4
.Ltmp184:
	and.w	r4, r0, r1
	bic.w	r0, lr, r0
	orr.w	lr, r0, r4
.Ltmp185:
	bne.w	.LBB0_3
@ %bb.4:
	add	r0, sp, #720
	add.w	r1, r10, #16
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	mov	r5, r10
	add.w	r9, r10, #88
	vst1.32	{d16, d17}, [r1]
	add.w	r1, r10, #32
	mov	r8, r9
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
	movs	r1, #104
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #688
	vstr	d16, [r10, #80]
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #800
	vst1.16	{d16, d17}, [r5], r1
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
	movw	r1, #701
	sub.w	r2, r1, lr
	orr.w	r2, r2, lr
.Ltmp187:
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
.Ltmp188:
	mov	r0, r10
.Ltmp189:
	and.w	r1, r1, r2, asr #31
	vstr	d16, [r8]
	sub.w	r6, lr, r1
.Ltmp190:
	mov	r1, r6
	bl	poly2_rotr_consttime
	mov	r0, r9
	mov	r1, r6
	bl	poly2_rotr_consttime
.Ltmp191:
	add.w	lr, sp, #880
.Ltmp192:
	mov	r0, r10
.Ltmp193:
	vld1.64	{d16, d17}, [lr:128]    @ 16-byte Reload
.Ltmp194:
	add.w	lr, sp, #896
.Ltmp195:
	vmov.32	r1, d16[0]
.Ltmp196:
	vld1.64	{d16, d17}, [lr:128]    @ 16-byte Reload
	vmov.32	r2, d16[0]
.Ltmp197:
	bl	poly3_mul_const
	movs	r0, #84
.Ltmp198:
	ldr.w	r1, [r10, #84]
	vld1.32	{d19}, [r9], r0
	movs	r6, #112
.Ltmp199:
	sub.w	r4, r7, #88
.Ltmp200:
	ldr.w	r0, [r9]
.Ltmp201:
	orr.w	r3, r1, r0
.Ltmp202:
	sbfx	r2, r0, #28, #1
.Ltmp203:
	mov	r0, r10
	vld1.32	{d20}, [r0], r6
.Ltmp204:
	sbfx	r1, r1, #28, #1
.Ltmp205:
	vorr	d21, d19, d20
	vdup.32	d16, r1
.Ltmp206:
	lsls	r1, r3, #3
.Ltmp207:
	mvn.w	r1, r1, asr #31
	vand	d22, d19, d16
	vdup.32	d18, r1
	mov	r1, r10
	vand	d23, d20, d18
	vdup.32	d17, r2
	vbic	d24, d17, d21
	movs	r2, #96
	veor	d22, d22, d23
	vldr	d25, [r10, #16]
	vldr	d26, [r10, #24]
	vand	d30, d25, d17
	veor	d22, d22, d24
	vldr	d23, [r10, #8]
	vst1.32	{d22}, [r1], r2
	vand	d24, d23, d17
	vand	d3, d26, d17
	vldr	d22, [r1]
	vand	d20, d20, d17
	vldr	d27, [r5]
	vorr	d31, d22, d23
	vand	d28, d22, d18
	vldr	d0, [r0]
	vorr	d29, d27, d25
	vand	d1, d27, d18
	vorr	d2, d0, d26
	vand	d4, d0, d18
	veor	d24, d28, d24
	vbic	d5, d16, d31
	veor	d30, d1, d30
	vbic	d28, d16, d29
	vbic	d1, d16, d2
	veor	d3, d4, d3
	veor	d24, d24, d5
	vand	d19, d19, d18
	veor	d28, d30, d28
	veor	d30, d3, d1
	vstr	d24, [r1]
	veor	d19, d19, d20
	vldr	d24, [r10, #32]
	vbic	d21, d16, d21
	vand	d27, d27, d16
	vand	d25, d25, d18
	vand	d0, d0, d16
	vand	d26, d26, d18
	vand	d23, d23, d18
	vand	d22, d22, d16
	vbic	d20, d17, d29
	vbic	d29, d17, d31
	vldr	d31, [r10, #120]
	vstr	d28, [r5]
	veor	d22, d22, d23
	vstr	d30, [r0]
	veor	d25, d27, d25
	vldr	d1, [r10, #128]
	veor	d26, d0, d26
	vldr	d30, [r10, #40]
	veor	d19, d19, d21
	vbic	d27, d17, d2
	vand	d23, d24, d17
	vand	d28, d24, d18
	vstr	d19, [r10, #88]
	vorr	d21, d1, d30
	vand	d0, d31, d16
	vorr	d24, d31, d24
	vand	d31, d31, d18
	vand	d2, d30, d18
	vand	d4, d30, d17
	vand	d3, d1, d16
	vand	d5, d1, d18
	veor	d20, d25, d20
	veor	d25, d26, d27
	veor	d22, d22, d29
	veor	d26, d0, d28
	vstr	d20, [r10, #16]
	vbic	d27, d17, d24
	vstr	d25, [r10, #24]
	veor	d23, d31, d23
	vstr	d22, [r10, #8]
	vbic	d24, d16, d24
	veor	d28, d3, d2
	vbic	d19, d17, d21
	vbic	d30, d16, d21
	veor	d29, d5, d4
	veor	d20, d26, d27
	veor	d21, d23, d24
	veor	d19, d28, d19
	veor	d22, d29, d30
	vstr	d20, [r10, #32]
	vstr	d21, [r10, #120]
	vstr	d19, [r10, #40]
	vstr	d22, [r10, #128]
	vldr	d19, [r10, #48]
	vldr	d20, [r10, #136]
	vand	d21, d19, d18
	vand	d22, d20, d16
	vorr	d23, d20, d19
	vand	d19, d19, d17
	vand	d20, d20, d18
	veor	d21, d22, d21
	vbic	d22, d17, d23
	veor	d19, d20, d19
	vbic	d20, d16, d23
	veor	d21, d21, d22
	veor	d19, d19, d20
	vstr	d21, [r10, #48]
	vstr	d19, [r10, #136]
	vldr	d19, [r10, #56]
	vldr	d20, [r10, #144]
	vand	d21, d19, d18
	vand	d22, d20, d16
	vorr	d23, d20, d19
	vand	d19, d19, d17
	vand	d20, d20, d18
	veor	d21, d22, d21
	vbic	d22, d17, d23
	veor	d19, d20, d19
	vbic	d20, d16, d23
	veor	d21, d21, d22
	veor	d19, d19, d20
	vstr	d21, [r10, #56]
	vstr	d19, [r10, #144]
	vldr	d19, [r10, #64]
	vldr	d20, [r10, #152]
	vand	d21, d19, d18
	vand	d22, d20, d16
	vorr	d23, d20, d19
	vand	d19, d19, d17
	vand	d20, d20, d18
	veor	d21, d22, d21
	vbic	d22, d17, d23
	veor	d19, d20, d19
	vbic	d20, d16, d23
	veor	d21, d21, d22
	veor	d19, d19, d20
	vstr	d21, [r10, #64]
	vstr	d19, [r10, #152]
	vldr	d19, [r10, #72]
	vldr	d20, [r10, #160]
	vand	d21, d19, d18
	vand	d22, d20, d16
	vorr	d23, d20, d19
	vand	d19, d19, d17
	vand	d20, d20, d18
	veor	d21, d22, d21
	vbic	d22, d17, d23
	veor	d19, d20, d19
	vbic	d20, d16, d23
	veor	d21, d21, d22
	veor	d19, d19, d20
	vstr	d21, [r10, #72]
	vstr	d19, [r10, #160]
	vldr	d19, [r8]
	vldr	d20, [r10, #80]
	vand	d22, d19, d16
	vorr	d21, d19, d20
	vand	d23, d20, d18
	vand	d18, d19, d18
	vand	d19, d20, d17
	vbic	d17, d17, d21
	veor	d20, d22, d23
	vbic	d16, d16, d21
	veor	d18, d18, d19
	veor	d17, d20, d17
	veor	d16, d18, d16
	vstr	d17, [r10, #80]
	ldr.w	r0, [r10, #84]
	vstr	d16, [r8]
	ldr.w	r1, [r9]
	bic	r0, r0, #-536870912
	str.w	r0, [r10, #84]
	bic	r0, r1, #-536870912
	str.w	r0, [r9]
.Ltmp208:
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
	movs	r0, #88
.Ltmp219:
	strh.w	r6, [r1, #1406]
	str.w	r6, [r1, #1402]
	add	r1, sp, #16
.Ltmp220:
	strh.w	r6, [r3, #1406]
	str.w	r6, [r3, #1402]
.Ltmp221:
	str	r0, [sp]
	mov	r0, r5
	bl	poly_mul_vec_aux
	add.w	r0, r5, #1392
	vld1.64	{d16, d17}, [r0:128]
	mov.w	r0, #1408
.LBB2_1:                                @ =>This Inner Loop Header: Depth=1
	adds	r1, r5, r6
	vld1.16	{d18, d19}, [r1:128], r0
	vld1.64	{d20, d21}, [r1:128]
	adds	r1, r4, r6
	adds	r6, #16
.Ltmp222:
	vext.16	q8, q8, q10, #5
.Ltmp223:
	cmp.w	r6, #1408
.Ltmp224:
	vadd.i16	q8, q8, q9
.Ltmp225:
	vst1.64	{d16, d17}, [r1:128]
	vorr	q8, q10, q10
	bne	.LBB2_1
@ %bb.2:
.Ltmp226:
	movs	r0, #0
	strh.w	r0, [r4, #1406]
	str.w	r0, [r4, #1402]
	ldr.w	r0, [r8]
	ldr.w	r1, [r9]
	subs	r0, r1, r0
.Ltmp227:
	itttt	eq
	subeq.w	r4, r7, #24
	moveq	sp, r4
	popeq.w	{r8, r9, r11}
	popeq	{r4, r5, r6, r7, pc}
	bl	__stack_chk_fail
.Ltmp228:
	.p2align	2
@ %bb.3:
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
	cmp	r1, #3
	beq.w	.LBB3_3
@ %bb.1:
	cmp	r1, #2
	bne.w	.LBB3_4
@ %bb.2:
	vld1.16	{d20, d21}, [r10:128]!
	add	r0, sp, #816
.Ltmp231:
	vmov.i32	q8, #0x0
.Ltmp232:
	movs	r1, #30
	vld1.64	{d22, d23}, [r10:128]
.Ltmp233:
	vmov.i32	q9, #0x0
.Ltmp234:
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp235:
	add	r0, sp, #768
	vext.16	q13, q11, q8, #7
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #640
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
.Ltmp236:
	add.w	r0, r8, #2
.Ltmp237:
	vld1.16	{d16[], d17[]}, [r0:16]
.Ltmp238:
	add	r0, sp, #784
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vmul.i16	q8, q8, q13
.Ltmp239:
	add.w	r0, r8, #16
.Ltmp240:
	vext.16	q4, q10, q11, #7
.Ltmp241:
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp242:
	add	r0, sp, #736
.Ltmp243:
	vmla.i16	q8, q12, q11
.Ltmp244:
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp245:
	add.w	r0, r8, #18
.Ltmp246:
	vld1.16	{d22[], d23[]}, [r0:16]
.Ltmp247:
	add	r0, sp, #832
.Ltmp248:
	vmla.i16	q8, q11, q4
.Ltmp249:
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
.Ltmp250:
	add.w	r0, r8, #4
.Ltmp251:
	vld1.16	{d22[], d23[]}, [r0:16]
.Ltmp252:
	add	r0, sp, #752
.Ltmp253:
	vext.16	q13, q4, q13, #7
.Ltmp254:
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	vmla.i16	q8, q11, q13
.Ltmp255:
	add	r0, sp, #672
.Ltmp256:
	vext.16	q11, q9, q10, #7
.Ltmp257:
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #20
.Ltmp258:
	vext.16	q1, q11, q4, #7
.Ltmp259:
	vld1.16	{d6[], d7[]}, [r0:16]
.Ltmp260:
	add.w	r0, r8, #6
.Ltmp261:
	vmla.i16	q8, q3, q1
.Ltmp262:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp263:
	add	r0, sp, #704
.Ltmp264:
	vext.16	q0, q1, q13, #7
.Ltmp265:
	vmul.i16	q13, q3, q13
.Ltmp266:
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	vmla.i16	q8, q10, q0
.Ltmp267:
	add	r0, sp, #624
.Ltmp268:
	vext.16	q10, q9, q11, #7
	vorr	q12, q10, q10
.Ltmp269:
	vext.16	q15, q10, q1, #7
.Ltmp270:
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #22
.Ltmp271:
	vld1.16	{d14[], d15[]}, [r0:16]
.Ltmp272:
	add.w	r0, r8, #8
.Ltmp273:
	vmla.i16	q8, q7, q15
.Ltmp274:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp275:
	add	r0, sp, #656
.Ltmp276:
	vext.16	q11, q15, q0, #7
.Ltmp277:
	vext.16	q2, q9, q12, #7
.Ltmp278:
	vmla.i16	q8, q10, q11
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp279:
	add	r0, sp, #576
.Ltmp280:
	vext.16	q10, q2, q15, #7
.Ltmp281:
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
	add.w	r0, r8, #24
.Ltmp282:
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp283:
	add	r0, sp, #688
.Ltmp284:
	vmla.i16	q8, q12, q10
.Ltmp285:
	vext.16	q5, q10, q11, #7
.Ltmp286:
	vext.16	q6, q9, q2, #7
.Ltmp287:
	vst1.64	{d10, d11}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #10
.Ltmp288:
	vld1.16	{d28[], d29[]}, [r0:16]
.Ltmp289:
	add	r0, sp, #608
	vmla.i16	q8, q14, q5
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp290:
	add.w	r0, r8, #26
.Ltmp291:
	vext.16	q9, q6, q10, #7
.Ltmp292:
	vld1.16	{d28[], d29[]}, [r0:16]
.Ltmp293:
	add	r0, sp, #592
	vmla.i16	q8, q14, q9
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #720
.Ltmp294:
	vext.16	q14, q9, q5, #7
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp295:
	add.w	r0, r8, #12
.Ltmp296:
	vld1.16	{d4[], d5[]}, [r0:16]
.Ltmp297:
	add	r0, sp, #800
	vmla.i16	q8, q2, q14
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
.Ltmp298:
	add	r0, sp, #832
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #640
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp299:
	add	r0, sp, #816
.Ltmp300:
	vmla.i16	q13, q14, q2
.Ltmp301:
	vmla.i16	q13, q7, q0
.Ltmp302:
	vmla.i16	q13, q12, q11
.Ltmp303:
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp304:
	mov	r0, r8
.Ltmp305:
	vmul.i16	q0, q14, q11
.Ltmp306:
	vld1.16	{d28[], d29[]}, [r0:16], r1
.Ltmp307:
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
	add	r1, sp, #832
.Ltmp309:
	vmla.i16	q0, q5, q4
.Ltmp310:
	vld1.64	{d28, d29}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #752
	vld1.64	{d8, d9}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #624
	vld1.64	{d4, d5}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #704
	vmla.i16	q0, q14, q11
.Ltmp311:
	vmla.i16	q0, q4, q1
	vld1.64	{d2, d3}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #576
.Ltmp312:
	vmla.i16	q0, q3, q2
.Ltmp313:
	vmla.i16	q0, q1, q15
	vld1.64	{d30, d31}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #656
.Ltmp314:
	vmla.i16	q0, q7, q15
	vld1.64	{d14, d15}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #608
	vld1.64	{d6, d7}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #592
	vld1.64	{d28, d29}, [r1:128]    @ 16-byte Reload
.Ltmp315:
	add	r1, sp, #800
.Ltmp316:
	vmla.i16	q0, q7, q10
.Ltmp317:
	vmov.i32	q10, #0x0
.Ltmp318:
	vmla.i16	q0, q12, q6
.Ltmp319:
	vext.16	q10, q10, q6, #7
.Ltmp320:
	vext.16	q12, q10, q9, #7
.Ltmp321:
	vmla.i16	q0, q3, q9
.Ltmp322:
	vld1.64	{d18, d19}, [r1:128]    @ 16-byte Reload
.Ltmp323:
	add	r1, sp, #816
.Ltmp324:
	vmla.i16	q0, q14, q10
.Ltmp325:
	vmla.i16	q0, q9, q12
.Ltmp326:
	vmul.i16	q9, q5, q11
	vld1.64	{d22, d23}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #736
	vld1.64	{d10, d11}, [r1:128]    @ 16-byte Reload
.Ltmp327:
	add.w	r1, r8, #28
.Ltmp328:
	vmla.i16	q9, q5, q11
.Ltmp329:
	vld1.16	{d22[], d23[]}, [r1:16]
.Ltmp330:
	add	r1, sp, #688
.Ltmp331:
	vmla.i16	q8, q11, q12
.Ltmp332:
	vmla.i16	q9, q4, q2
.Ltmp333:
	vmla.i16	q9, q1, q15
.Ltmp334:
	vld1.64	{d30, d31}, [r1:128]    @ 16-byte Reload
.Ltmp335:
	add.w	r1, r8, #14
.Ltmp336:
	vmla.i16	q13, q14, q15
.Ltmp337:
	vmov.i32	q14, #0x0
.Ltmp338:
	vmla.i16	q9, q7, q6
.Ltmp339:
	vmov.i32	q1, #0x0
.Ltmp340:
	vmla.i16	q9, q3, q10
.Ltmp341:
	vext.16	q10, q14, q10, #7
.Ltmp342:
	vld1.16	{d28[], d29[]}, [r1:16]
	add	r1, sp, #720
.Ltmp343:
	vmla.i16	q0, q11, q10
	vld1.64	{d6, d7}, [r1:128]      @ 16-byte Reload
.Ltmp344:
	add	r1, sp, #800
.Ltmp345:
	vmla.i16	q13, q11, q3
.Ltmp346:
	vext.16	q15, q12, q3, #7
	vext.16	q11, q10, q12, #7
.Ltmp347:
	vmla.i16	q8, q14, q15
.Ltmp348:
	vld1.64	{d24, d25}, [r1:128]    @ 16-byte Reload
.Ltmp349:
	vmla.i16	q0, q14, q11
.Ltmp350:
	mov	r1, lr
.Ltmp351:
	vmla.i16	q9, q12, q10
.Ltmp352:
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp353:
	movs	r0, #48
.Ltmp354:
	vmla.i16	q13, q12, q15
.Ltmp355:
	vext.16	q10, q1, q10, #7
.Ltmp356:
	vmla.i16	q8, q12, q11
.Ltmp357:
	vmla.i16	q0, q12, q10
.Ltmp358:
	vmla.i16	q9, q14, q10
.Ltmp359:
	vst1.16	{d18, d19}, [r1:128], r0
	add.w	r0, lr, #32
	vst1.64	{d26, d27}, [r1:128]
	vst1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, #16
	vst1.64	{d0, d1}, [r0:128]
	b.w	.LBB3_17
.LBB3_3:
	movs	r0, #32
	add.w	r1, r10, #16
	vld1.16	{d22, d23}, [r10:128], r0
.Ltmp360:
	vmov.i32	q8, #0x0
.Ltmp361:
	add	r0, sp, #752
.Ltmp362:
	vmov.i32	q10, #0x0
.Ltmp363:
	vld1.64	{d18, d19}, [r1:128]
.Ltmp364:
	mov	r1, r8
	vorr	q14, q9, q9
.Ltmp365:
	vld1.64	{d6, d7}, [r10:128]
.Ltmp366:
	vext.16	q1, q3, q8, #7
	vext.16	q15, q9, q3, #7
.Ltmp367:
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
.Ltmp368:
	vext.16	q8, q15, q1, #7
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
.Ltmp369:
	add	r0, sp, #624
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #36
.Ltmp370:
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp371:
	add	r0, sp, #832
	vmul.i16	q2, q12, q8
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp372:
	add.w	r0, r8, #34
.Ltmp373:
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp374:
	add	r0, sp, #256
	vmla.i16	q2, q12, q1
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #64
.Ltmp375:
	vext.16	q13, q11, q9, #7
	vst1.64	{d2, d3}, [r0:128]      @ 16-byte Spill
.Ltmp376:
	add	r0, sp, #704
	vext.16	q6, q13, q15, #7
	vorr	q15, q13, q13
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
.Ltmp377:
	add.w	r0, r8, #38
.Ltmp378:
	vext.16	q12, q10, q11, #7
.Ltmp379:
	vld1.16	{d18[], d19[]}, [r0:16]
.Ltmp380:
	add	r0, sp, #320
.Ltmp381:
	vext.16	q8, q6, q8, #7
.Ltmp382:
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmla.i16	q2, q9, q8
.Ltmp383:
	add	r0, sp, #160
	vext.16	q9, q12, q13, #7
	vorr	q7, q8, q8
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
.Ltmp384:
	add	r0, sp, #672
	vorr	q4, q9, q9
	vext.16	q13, q9, q6, #7
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
.Ltmp385:
	add	r0, sp, #416
	vst1.64	{d12, d13}, [r0:128]    @ 16-byte Spill
.Ltmp386:
	add	r0, sp, #48
	vst1.64	{d14, d15}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #40
.Ltmp387:
	vext.16	q0, q13, q8, #7
.Ltmp388:
	vld1.16	{d22[], d23[]}, [r0:16]
	add	r0, sp, #352
	vorr	q8, q0, q0
.Ltmp389:
	vmla.i16	q2, q11, q0
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #544
.Ltmp390:
	vext.16	q11, q10, q12, #7
.Ltmp391:
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp392:
	add	r0, sp, #736
	vext.16	q12, q11, q9, #7
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
.Ltmp393:
	add	r0, sp, #640
	vorr	q5, q12, q12
	vext.16	q0, q12, q13, #7
	vst1.64	{d8, d9}, [r0:128]      @ 16-byte Spill
.Ltmp394:
	add	r0, sp, #272
.Ltmp395:
	vext.16	q9, q10, q11, #7
.Ltmp396:
	vst1.64	{d0, d1}, [r0:128]      @ 16-byte Spill
.Ltmp397:
	add.w	r0, r8, #42
.Ltmp398:
	vext.16	q13, q0, q8, #7
.Ltmp399:
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #384
.Ltmp400:
	vmla.i16	q2, q8, q13
.Ltmp401:
	vext.16	q11, q9, q12, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp402:
	add	r0, sp, #496
.Ltmp403:
	vext.16	q12, q11, q0, #7
.Ltmp404:
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
.Ltmp405:
	add	r0, sp, #720
	vorr	q0, q12, q12
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
.Ltmp406:
	add	r0, sp, #656
.Ltmp407:
	vext.16	q12, q12, q13, #7
.Ltmp408:
	vst1.64	{d10, d11}, [r0:128]    @ 16-byte Spill
.Ltmp409:
	add	r0, sp, #464
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #44
.Ltmp410:
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #400
.Ltmp411:
	vmla.i16	q2, q8, q12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp412:
	add	r0, sp, #784
.Ltmp413:
	vext.16	q8, q10, q9, #7
.Ltmp414:
	vext.16	q9, q8, q11, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vorr	q8, q11, q11
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #592
.Ltmp415:
	vext.16	q10, q9, q0, #7
	vorr	q9, q0, q0
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp416:
	movs	r0, #46
.Ltmp417:
	vld1.16	{d22[], d23[]}, [r1:16], r0
.Ltmp418:
	add	r0, sp, #512
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #368
	vext.16	q11, q10, q12, #7
.Ltmp419:
	vld1.16	{d20[], d21[]}, [r1:16]
.Ltmp420:
	mov	r1, lr
.Ltmp421:
	vmla.i16	q2, q10, q11
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #176
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #144
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
.Ltmp422:
	add.w	r0, r8, #32
.Ltmp423:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp424:
	add	r0, sp, #480
	vmul.i16	q13, q10, q14
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp425:
	add.w	r0, r8, #16
	vorr	q14, q3, q3
.Ltmp426:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp427:
	add	r0, sp, #688
	vmla.i16	q13, q10, q3
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp428:
	add.w	r0, r8, #2
.Ltmp429:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp430:
	add	r0, sp, #128
	vmla.i16	q13, q10, q1
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp431:
	add.w	r0, r8, #18
.Ltmp432:
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #288
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp433:
	add	r0, sp, #768
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vmla.i16	q13, q10, q11
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp434:
	add.w	r0, r8, #4
.Ltmp435:
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp436:
	add	r0, sp, #432
.Ltmp437:
	vmla.i16	q13, q11, q15
.Ltmp438:
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #624
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp439:
	add.w	r0, r8, #20
.Ltmp440:
	vmla.i16	q13, q12, q10
.Ltmp441:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp442:
	add	r0, sp, #832
	vorr	q15, q10, q10
.Ltmp443:
	vmla.i16	q13, q10, q6
.Ltmp444:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp445:
	add.w	r0, r8, #6
	vorr	q6, q14, q14
.Ltmp446:
	vmla.i16	q13, q10, q4
.Ltmp447:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp448:
	add	r0, sp, #608
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp449:
	add.w	r0, r8, #22
.Ltmp450:
	vmla.i16	q13, q10, q7
.Ltmp451:
	vld1.16	{d20[], d21[]}, [r0:16]
.Ltmp452:
	add	r0, sp, #240
	vorr	q7, q9, q9
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #320
	vmla.i16	q13, q10, q12
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp453:
	add.w	r0, r8, #8
.Ltmp454:
	vld1.16	{d24[], d25[]}, [r0:16]
.Ltmp455:
	add	r0, sp, #96
.Ltmp456:
	vmla.i16	q13, q2, q5
.Ltmp457:
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #544
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp458:
	add.w	r0, r8, #24
.Ltmp459:
	vmla.i16	q13, q12, q10
.Ltmp460:
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #224
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #272
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
.Ltmp461:
	vmla.i16	q13, q10, q5
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
.Ltmp462:
	add.w	r0, r8, #10
.Ltmp463:
	vmla.i16	q13, q0, q8
.Ltmp464:
	vld1.16	{d16[], d17[]}, [r0:16]
.Ltmp465:
	add	r0, sp, #576
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #496
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp466:
	add.w	r0, r8, #26
.Ltmp467:
	vmla.i16	q13, q8, q10
.Ltmp468:
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #208
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp469:
	add	r0, sp, #16
	vmla.i16	q13, q8, q9
	vst1.64	{d14, d15}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #384
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
.Ltmp470:
	add.w	r0, r8, #12
.Ltmp471:
	vmla.i16	q13, q4, q9
.Ltmp472:
	vld1.16	{d16[], d17[]}, [r0:16]
.Ltmp473:
	add	r0, sp, #528
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #464
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp474:
	add.w	r0, r8, #28
.Ltmp475:
	vmla.i16	q13, q8, q10
.Ltmp476:
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #192
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp477:
	add	r0, sp, #784
.Ltmp478:
	vmla.i16	q13, q8, q3
.Ltmp479:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp480:
	add	r0, sp, #336
.Ltmp481:
	vmov.i32	q8, #0x0
	vext.16	q8, q8, q10, #7
.Ltmp482:
	vext.16	q10, q8, q9, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #448
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #400
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp483:
	add.w	r0, r8, #14
.Ltmp484:
	vmla.i16	q13, q9, q10
.Ltmp485:
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #80
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
.Ltmp486:
	add	r0, sp, #368
.Ltmp487:
	vext.16	q10, q10, q3, #7
.Ltmp488:
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #560
	vmla.i16	q13, q8, q12
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
.Ltmp489:
	add.w	r0, r8, #30
.Ltmp490:
	vld1.16	{d24[], d25[]}, [r0:16]
	add	r0, sp, #112
.Ltmp491:
	vmla.i16	q13, q12, q10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #288
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp492:
	add	r0, sp, #64
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #480
	vmul.i16	q8, q10, q8
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp493:
	add	r0, sp, #768
.Ltmp494:
	vmla.i16	q8, q14, q6
.Ltmp495:
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp496:
	add	r0, sp, #32
.Ltmp497:
	vmla.i16	q8, q11, q14
	vorr	q11, q15, q15
.Ltmp498:
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #624
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp499:
	add	r0, sp, #416
.Ltmp500:
	vmla.i16	q8, q15, q14
.Ltmp501:
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #832
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
	vmla.i16	q8, q15, q14
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp502:
	add	r0, sp, #48
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp503:
	add	r0, sp, #816
.Ltmp504:
	vmla.i16	q8, q14, q15
.Ltmp505:
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #224
	vmla.i16	q8, q2, q15
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp506:
	add	r0, sp, #544
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #208
	vmla.i16	q8, q15, q2
.Ltmp507:
	vmla.i16	q8, q0, q5
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
.Ltmp508:
	add	r0, sp, #496
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #192
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
.Ltmp509:
	add	r0, sp, #464
.Ltmp510:
	vmla.i16	q8, q0, q2
.Ltmp511:
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp512:
	add	r0, sp, #368
.Ltmp513:
	vmla.i16	q8, q4, q7
.Ltmp514:
	vmla.i16	q8, q1, q2
.Ltmp515:
	vmla.i16	q8, q9, q3
.Ltmp516:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp517:
	add	r0, sp, #704
.Ltmp518:
	vmla.i16	q8, q12, q9
.Ltmp519:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #688
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	vmul.i16	q12, q12, q9
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #752
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp520:
	add	r0, sp, #480
.Ltmp521:
	vmla.i16	q12, q5, q6
.Ltmp522:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #128
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
.Ltmp523:
	add	r0, sp, #768
.Ltmp524:
	vmla.i16	q12, q9, q3
.Ltmp525:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp526:
	add	r0, sp, #672
.Ltmp527:
	vmla.i16	q12, q4, q9
.Ltmp528:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #160
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
.Ltmp529:
	add	r0, sp, #256
.Ltmp530:
	vmla.i16	q12, q10, q9
.Ltmp531:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #432
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp532:
	add	r0, sp, #416
.Ltmp533:
	vmla.i16	q12, q9, q6
.Ltmp534:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp535:
	add	r0, sp, #640
.Ltmp536:
	vmla.i16	q12, q2, q9
.Ltmp537:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp538:
	add	r0, sp, #832
.Ltmp539:
	vmla.i16	q12, q11, q9
.Ltmp540:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp541:
	add	r0, sp, #608
.Ltmp542:
	vmla.i16	q12, q9, q10
.Ltmp543:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #816
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp544:
	add	r0, sp, #656
.Ltmp545:
	vmla.i16	q12, q9, q11
.Ltmp546:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #720
	vmla.i16	q12, q14, q9
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp547:
	add	r0, sp, #320
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #96
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
.Ltmp548:
	add	r0, sp, #272
.Ltmp549:
	vmla.i16	q12, q9, q14
.Ltmp550:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp551:
	add	r0, sp, #592
.Ltmp552:
	vmla.i16	q12, q7, q9
.Ltmp553:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp554:
	add	r0, sp, #784
.Ltmp555:
	vmla.i16	q12, q15, q9
.Ltmp556:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp557:
	add	r0, sp, #576
.Ltmp558:
	vmla.i16	q12, q11, q9
.Ltmp559:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #16
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp560:
	add	r0, sp, #800
.Ltmp561:
	vmla.i16	q12, q9, q11
.Ltmp562:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #336
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp563:
	add	r0, sp, #384
.Ltmp564:
	vmla.i16	q12, q0, q9
.Ltmp565:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp566:
	add	r0, sp, #528
.Ltmp567:
	vmla.i16	q12, q9, q11
.Ltmp568:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #304
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp569:
	add	r0, sp, #448
.Ltmp570:
	vmla.i16	q12, q9, q15
.Ltmp571:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp572:
	add	r0, sp, #400
.Ltmp573:
	vmla.i16	q12, q1, q9
.Ltmp574:
	vmov.i32	q9, #0x0
.Ltmp575:
	vext.16	q1, q9, q11, #7
.Ltmp576:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #80
	vmla.i16	q12, q9, q1
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp577:
	add	r0, sp, #560
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp578:
	add	r0, sp, #688
.Ltmp579:
	vmla.i16	q12, q9, q11
.Ltmp580:
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #704
	vmul.i16	q0, q11, q3
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp581:
	add	r0, sp, #672
	vorr	q3, q4, q4
.Ltmp582:
	vmla.i16	q0, q5, q11
.Ltmp583:
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp584:
	add	r0, sp, #288
	vorr	q5, q7, q7
.Ltmp585:
	vmla.i16	q0, q4, q11
.Ltmp586:
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp587:
	add	r0, sp, #640
.Ltmp588:
	vmla.i16	q0, q11, q6
.Ltmp589:
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp590:
	add	r0, sp, #32
.Ltmp591:
	vmla.i16	q0, q2, q11
.Ltmp592:
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #608
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
.Ltmp593:
	add	r0, sp, #656
.Ltmp594:
	vmla.i16	q0, q11, q10
.Ltmp595:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp596:
	add	r0, sp, #240
.Ltmp597:
	vmla.i16	q0, q2, q10
.Ltmp598:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp599:
	add	r0, sp, #592
.Ltmp600:
	vmla.i16	q0, q10, q14
.Ltmp601:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #784
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp602:
	add	r0, sp, #224
.Ltmp603:
	vmla.i16	q0, q7, q10
.Ltmp604:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #576
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
.Ltmp605:
	add	r0, sp, #800
.Ltmp606:
	vmla.i16	q0, q10, q15
.Ltmp607:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #336
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
.Ltmp608:
	add	r0, sp, #208
.Ltmp609:
	vmla.i16	q0, q7, q10
.Ltmp610:
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #528
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #448
	vmla.i16	q0, q10, q11
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
.Ltmp611:
	add	r0, sp, #192
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
.Ltmp612:
	add	r0, sp, #752
.Ltmp613:
	vmla.i16	q0, q4, q10
.Ltmp614:
	vext.16	q10, q1, q10, #7
.Ltmp615:
	vmla.i16	q0, q14, q1
.Ltmp616:
	vmul.i16	q14, q3, q6
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
.Ltmp617:
	add	r0, sp, #432
.Ltmp618:
	vmla.i16	q0, q9, q10
.Ltmp619:
	vmla.i16	q14, q3, q6
.Ltmp620:
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
.Ltmp621:
	add	r0, sp, #720
.Ltmp622:
	vmla.i16	q14, q3, q6
.Ltmp623:
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #176
	vmla.i16	q14, q2, q3
.Ltmp624:
	vmla.i16	q14, q5, q15
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
.Ltmp625:
	add	r0, sp, #560
.Ltmp626:
	vmla.i16	q13, q15, q10
.Ltmp627:
	vmla.i16	q14, q7, q11
.Ltmp628:
	vmov.i32	q11, #0x0
.Ltmp629:
	vmla.i16	q14, q4, q1
.Ltmp630:
	vext.16	q11, q11, q1, #7
.Ltmp631:
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #112
	vmla.i16	q8, q15, q1
.Ltmp632:
	vmla.i16	q14, q9, q11
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
.Ltmp633:
	movs	r0, #80
.Ltmp634:
	vmla.i16	q12, q9, q10
.Ltmp635:
	vst1.16	{d28, d29}, [r1:128], r0
	add	r0, sp, #144
.Ltmp636:
	vmla.i16	q0, q9, q11
.Ltmp637:
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add.w	r0, lr, #64
	vst1.64	{d18, d19}, [r1:128]
.Ltmp638:
	vmla.i16	q12, q15, q11
.Ltmp639:
	vst1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, #16
	vst1.64	{d0, d1}, [r0:128]
	add.w	r0, lr, #48
	vst1.64	{d26, d27}, [r0:128]
	add.w	r0, lr, #32
	vst1.64	{d24, d25}, [r0:128]
	b	.LBB3_17
.LBB3_4:
	lsr.w	r11, r1, #1
	add.w	r0, r8, r11, lsl #4
	str	r0, [sp, #816]          @ 4-byte Spill
	add.w	r0, r10, r11, lsl #4
	str	r0, [sp, #800]          @ 4-byte Spill
	sub.w	r0, r1, r1, lsr #1
	str	r0, [sp, #832]          @ 4-byte Spill
	movs	r0, #0
	cmp.w	r0, r1, lsr #1
	beq	.LBB3_7
@ %bb.5:
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
	vld1.16	{d16, d17}, [r5:128]!
	adds	r6, r3, r1
	subs	r2, #1
	vld1.64	{d18, d19}, [r0:128]
	add.w	r0, r4, r12
.Ltmp640:
	vadd.i16	q8, q8, q9
.Ltmp641:
	vst1.16	{d16, d17}, [r4:128]!
	vld1.16	{d18, d19}, [r3:128]!
	vld1.64	{d16, d17}, [r6:128]
.Ltmp642:
	vadd.i16	q8, q9, q8
.Ltmp643:
	vst1.64	{d16, d17}, [r0:128]
	bne	.LBB3_6
.LBB3_7:
	ldr	r0, [sp, #832]          @ 4-byte Reload
	ldr	r4, [r7, #8]
	cmp	r0, r11
	beq	.LBB3_9
@ %bb.8:
	ldr	r0, [sp, #800]          @ 4-byte Reload
	add.w	r0, r0, r11, lsl #4
	vld1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, r11, lsl #4
	vst1.64	{d16, d17}, [r0:128]
	ldr	r0, [sp, #816]          @ 4-byte Reload
	add.w	r0, r0, r11, lsl #4
	vld1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, r4, lsl #4
	vst1.64	{d16, d17}, [r0:128]
.LBB3_9:
	ldr	r4, [sp, #832]          @ 4-byte Reload
	mov	r6, r11
	mov	r0, r9
	mov	r2, lr
	str	r4, [sp]
	mov	r5, lr
	add.w	r11, r9, r4, lsl #5
	add.w	r3, lr, r4, lsl #4
	mov	r1, r11
	bl	poly_mul_vec_aux
	ldr	r0, [r7, #8]
	mov	r1, r11
	str	r4, [sp]
	bic	r4, r0, #1
	ldr	r2, [sp, #800]          @ 4-byte Reload
	ldr	r3, [sp, #816]          @ 4-byte Reload
	add.w	r0, r5, r4, lsl #4
	bl	poly_mul_vec_aux
	mov	r1, r11
	mov	r0, r5
	mov	r2, r10
	mov	r3, r8
	str	r6, [sp]
	mov	r11, r6
	bl	poly_mul_vec_aux
	cbz	r4, .LBB3_12
@ %bb.10:
	lsl.w	r0, r11, #5
	mov	r1, r4
	mov	r2, r5
	mov	r3, r9
.LBB3_11:                               @ =>This Inner Loop Header: Depth=1
	adds	r6, r2, r0
	vld1.16	{d16, d17}, [r2:128]!
	subs	r1, #1
	vld1.64	{d18, d19}, [r3:128]
.Ltmp644:
	vsub.i16	q8, q9, q8
.Ltmp645:
	vld1.64	{d20, d21}, [r6:128]
.Ltmp646:
	vsub.i16	q8, q8, q10
.Ltmp647:
	vst1.16	{d16, d17}, [r3:128]!
	bne	.LBB3_11
.LBB3_12:
	ldr	r1, [sp, #832]          @ 4-byte Reload
	cmp	r1, r11
	lsl.w	r0, r1, #1
	beq	.LBB3_14
@ %bb.13:
	add.w	r1, r5, r11, lsl #6
	vld1.64	{d16, d17}, [r1:128]
	add.w	r1, r9, r4, lsl #4
	vld1.64	{d18, d19}, [r1:128]
.Ltmp648:
	vsub.i16	q8, q9, q8
.Ltmp649:
	vst1.64	{d16, d17}, [r1:128]
	movs	r1, #16
	orr.w	r1, r1, r11, lsl #6
	add	r1, r5
	vld1.64	{d16, d17}, [r1:128]
	ldr	r1, [r7, #8]
	orr	r1, r1, #1
	add.w	r1, r9, r1, lsl #4
	vld1.64	{d18, d19}, [r1:128]
.Ltmp650:
	vsub.i16	q8, q9, q8
.Ltmp651:
	vst1.64	{d16, d17}, [r1:128]
.LBB3_14:
	cbz	r0, .LBB3_17
@ %bb.15:
	add.w	r1, r5, r11, lsl #4
.LBB3_16:                               @ =>This Inner Loop Header: Depth=1
	vld1.64	{d16, d17}, [r1:128]
	subs	r0, #1
	vld1.16	{d18, d19}, [r9:128]!
.Ltmp652:
	vadd.i16	q8, q9, q8
.Ltmp653:
	vst1.16	{d16, d17}, [r1:128]!
	bne	.LBB3_16
.LBB3_17:
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
