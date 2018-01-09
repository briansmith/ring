/*	$OpenBSD: asm.h,v 1.7 2004/10/20 12:49:15 pefo Exp $ */

/*
 * Copyright (c) 2001-2002 Opsycon AB  (www.opsycon.se / www.opsycon.com)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#pragma once

#define __bionic_asm_align 16

#undef __bionic_asm_custom_entry
#undef __bionic_asm_custom_end
#define __bionic_asm_custom_entry(f) .ent f
#define __bionic_asm_custom_end(f) .end f

#define	_MIPS_ISA_MIPS1	1	/* R2000/R3000 */
#define	_MIPS_ISA_MIPS2	2	/* R4000/R6000 */
#define	_MIPS_ISA_MIPS3	3	/* R4000 */
#define	_MIPS_ISA_MIPS4	4	/* TFP (R1x000) */
#define	_MIPS_ISA_MIPS5 5
#define	_MIPS_ISA_MIPS32 6
#define	_MIPS_ISA_MIPS64 7

#if !defined(ABICALLS) && !defined(_NO_ABICALLS)
#define	ABICALLS	.abicalls
#endif

#if defined(ABICALLS) && !defined(_KERNEL)
	ABICALLS
#endif

/*
 * Define how to access unaligned data word
 */
#define LWLO    lwl
#define LWHI    lwr
#define	SWLO	swl
#define	SWHI	swr
#define LDLO    ldl
#define LDHI    ldr
#define	SDLO	sdl
#define	SDHI	sdr

/*
 *  Define programming environment for ABI.
 */
#if defined(ABICALLS) && !defined(_KERNEL) && !defined(_STANDALONE)

#if (_MIPS_SIM == _ABIO32) || (_MIPS_SIM == _ABI32)
#define NARGSAVE	4

#define	SETUP_GP		\
	.set	noreorder;	\
	.cpload	$t9;		\
	.set	reorder;

#define	SAVE_GP(x)		\
	.cprestore x

#define	SETUP_GP64(gpoff, name)
#define	RESTORE_GP64
#endif

#if (_MIPS_SIM == _ABI64) || (_MIPS_SIM == _ABIN32)
#define NARGSAVE	0

#define	SETUP_GP
#define	SAVE_GP(x)
#define	SETUP_GP64(gpoff, name)	\
	.cpsetup $t9, gpoff, name
#define	RESTORE_GP64		\
	.cpreturn
#endif

#define	MKFSIZ(narg,locals) (((narg+locals)*REGSZ+31)&(~31))

#else /* defined(ABICALLS) && !defined(_KERNEL) */

#define	NARGSAVE	4
#define	SETUP_GP
#define	SAVE_GP(x)

#define	ALIGNSZ		16	/* Stack layout alignment */
#define	FRAMESZ(sz)	(((sz) + (ALIGNSZ-1)) & ~(ALIGNSZ-1))

#endif

/*
 *  Basic register operations based on selected ISA
 */
#if (_MIPS_ISA == _MIPS_ISA_MIPS1 || _MIPS_ISA == _MIPS_ISA_MIPS2 || _MIPS_ISA == _MIPS_ISA_MIPS32)
#define REGSZ		4	/* 32 bit mode register size */
#define LOGREGSZ	2	/* log rsize */
#define	REG_S	sw
#define	REG_L	lw
#define	CF_SZ		24	/* Call frame size */
#define	CF_ARGSZ	16	/* Call frame arg size */
#define	CF_RA_OFFS	20	/* Call ra save offset */
#endif

#if (_MIPS_ISA == _MIPS_ISA_MIPS3 || _MIPS_ISA == _MIPS_ISA_MIPS4 || _MIPS_ISA == _MIPS_ISA_MIPS64)
#define REGSZ		8	/* 64 bit mode register size */
#define LOGREGSZ	3	/* log rsize */
#define	REG_S	sd
#define	REG_L	ld
#define	CF_SZ		48	/* Call frame size (multiple of ALIGNSZ) */
#define	CF_ARGSZ	32	/* Call frame arg size */
#define	CF_RA_OFFS	40	/* Call ra save offset */
#endif

#define REGSZ_FP	 8	/* 64 bit FP register size */

#ifndef __LP64__
#define	PTR_L		lw
#define	PTR_S		sw
#define	PTR_SUB		sub
#define	PTR_ADD		add
#define	PTR_SUBU	subu
#define	PTR_ADDU	addu
#define LI		li
#define	LA		la
#define	PTR_SLL		sll
#define	PTR_SRL		srl
#define	PTR_VAL		.word
#else
#define	PTR_L		ld
#define	PTR_S		sd
#define	PTR_ADD		dadd
#define	PTR_SUB		dsub
#define	PTR_SUBU	dsubu
#define	PTR_ADDU	daddu
#define LI		dli
#define LA		dla
#define	PTR_SLL		dsll
#define	PTR_SRL		dsrl
#define	PTR_VAL		.dword
#endif

/*
 * LEAF(x, fsize)
 *
 *	Declare a leaf routine.
 */
#define LEAF(x, fsize)		\
	.align	3;		\
	.globl x;		\
	.ent x, 0;		\
x: ;				\
	.cfi_startproc; \
	.frame $sp, fsize, $ra;	\
	SETUP_GP		\

/*
 * NON_LEAF(x)
 *
 *	Declare a non-leaf routine (a routine that makes other C calls).
 */
#define NON_LEAF(x, fsize, retpc) \
	.align	3;		\
	.globl x;		\
	.ent x, 0;		\
x: ;				\
	.cfi_startproc; \
	.frame $sp, fsize, retpc; \
	SETUP_GP		\
