// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#include <openssl/asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && defined(__APPLE__)
.section	__DATA,__const
.p2align	6


L$bswap_mask:
.quad	0x08090a0b0c0d0e0f, 0x0001020304050607








L$gfpoly:
.quad	1, 0xc200000000000000


L$gfpoly_and_internal_carrybit:
.quad	1, 0xc200000000000001





L$ctr_pattern:
.quad	0, 0
.quad	1, 0
L$inc_2blocks:
.quad	2, 0
.quad	3, 0
L$inc_4blocks:
.quad	4, 0

.text	
.globl	_gcm_gmult_vpclmulqdq_avx10
.private_extern _gcm_gmult_vpclmulqdq_avx10

.p2align	5
_gcm_gmult_vpclmulqdq_avx10:


_CET_ENDBR



	vmovdqu	(%rdi),%xmm0
	vmovdqu	L$bswap_mask(%rip),%xmm1
	vmovdqu	256-16(%rsi),%xmm2
	vmovdqu	L$gfpoly(%rip),%xmm3
	vpshufb	%xmm1,%xmm0,%xmm0

	vpclmulqdq	$0x00,%xmm2,%xmm0,%xmm4
	vpclmulqdq	$0x01,%xmm2,%xmm0,%xmm5
	vpclmulqdq	$0x10,%xmm2,%xmm0,%xmm6
	vpxord	%xmm6,%xmm5,%xmm5
	vpclmulqdq	$0x01,%xmm4,%xmm3,%xmm6
	vpshufd	$0x4e,%xmm4,%xmm4
	vpternlogd	$0x96,%xmm6,%xmm4,%xmm5
	vpclmulqdq	$0x11,%xmm2,%xmm0,%xmm0
	vpclmulqdq	$0x01,%xmm5,%xmm3,%xmm4
	vpshufd	$0x4e,%xmm5,%xmm5
	vpternlogd	$0x96,%xmm4,%xmm5,%xmm0


	vpshufb	%xmm1,%xmm0,%xmm0
	vmovdqu	%xmm0,(%rdi)
	ret



.globl	_gcm_init_vpclmulqdq_avx10
.private_extern _gcm_init_vpclmulqdq_avx10

.p2align	5
_gcm_init_vpclmulqdq_avx10:


_CET_ENDBR

	leaq	256-32(%rdi),%r8



	vpshufd	$0x4e,(%rsi),%xmm3
















	vpshufd	$0xd3,%xmm3,%xmm0
	vpsrad	$31,%xmm0,%xmm0
	vpaddq	%xmm3,%xmm3,%xmm3

	vpternlogd	$0x78,L$gfpoly_and_internal_carrybit(%rip),%xmm0,%xmm3


	vbroadcasti32x4	L$gfpoly(%rip),%ymm5








	vpclmulqdq	$0x00,%xmm3,%xmm3,%xmm0
	vpclmulqdq	$0x01,%xmm3,%xmm3,%xmm1
	vpclmulqdq	$0x10,%xmm3,%xmm3,%xmm2
	vpxord	%xmm2,%xmm1,%xmm1
	vpclmulqdq	$0x01,%xmm0,%xmm5,%xmm2
	vpshufd	$0x4e,%xmm0,%xmm0
	vpternlogd	$0x96,%xmm2,%xmm0,%xmm1
	vpclmulqdq	$0x11,%xmm3,%xmm3,%xmm4
	vpclmulqdq	$0x01,%xmm1,%xmm5,%xmm0
	vpshufd	$0x4e,%xmm1,%xmm1
	vpternlogd	$0x96,%xmm0,%xmm1,%xmm4



	vinserti128	$1,%xmm3,%ymm4,%ymm3
	vinserti128	$1,%xmm4,%ymm4,%ymm4

	vmovdqu8	%ymm3,(%r8)





	movl	$7,%eax
L$precompute_next__func1:
	subq	$32,%r8
	vpclmulqdq	$0x00,%ymm4,%ymm3,%ymm0
	vpclmulqdq	$0x01,%ymm4,%ymm3,%ymm1
	vpclmulqdq	$0x10,%ymm4,%ymm3,%ymm2
	vpxord	%ymm2,%ymm1,%ymm1
	vpclmulqdq	$0x01,%ymm0,%ymm5,%ymm2
	vpshufd	$0x4e,%ymm0,%ymm0
	vpternlogd	$0x96,%ymm2,%ymm0,%ymm1
	vpclmulqdq	$0x11,%ymm4,%ymm3,%ymm3
	vpclmulqdq	$0x01,%ymm1,%ymm5,%ymm0
	vpshufd	$0x4e,%ymm1,%ymm1
	vpternlogd	$0x96,%ymm0,%ymm1,%ymm3

	vmovdqu8	%ymm3,(%r8)
	decl	%eax
	jnz	L$precompute_next__func1

	vzeroupper
	ret



.globl	_gcm_ghash_vpclmulqdq_avx10_256
.private_extern _gcm_ghash_vpclmulqdq_avx10_256

.p2align	5
_gcm_ghash_vpclmulqdq_avx10_256:


_CET_ENDBR






	vmovdqu	L$bswap_mask(%rip),%xmm4
	vmovdqu	L$gfpoly(%rip),%xmm10


	vmovdqu	(%rdi),%xmm5
	vpshufb	%xmm4,%xmm5,%xmm5


	cmpq	$32,%rcx
	jb	L$aad_blockbyblock__func1



	vshufi64x2	$0,%ymm4,%ymm4,%ymm4
	vshufi64x2	$0,%ymm10,%ymm10,%ymm10


	vmovdqu8	256-32(%rsi),%ymm9

	cmpq	$128-1,%rcx
	jbe	L$aad_loop_1x__func1


	vmovdqu8	256-128(%rsi),%ymm6
	vmovdqu8	256-96(%rsi),%ymm7
	vmovdqu8	256-64(%rsi),%ymm8


L$aad_loop_4x__func1:
	vmovdqu8	0(%rdx),%ymm0
	vmovdqu8	32(%rdx),%ymm1
	vmovdqu8	64(%rdx),%ymm2
	vmovdqu8	96(%rdx),%ymm3
	vpshufb	%ymm4,%ymm0,%ymm0
	vpxord	%ymm5,%ymm0,%ymm0
	vpshufb	%ymm4,%ymm1,%ymm1
	vpshufb	%ymm4,%ymm2,%ymm2
	vpshufb	%ymm4,%ymm3,%ymm3
	vpclmulqdq	$0x00,%ymm6,%ymm0,%ymm5
	vpclmulqdq	$0x00,%ymm7,%ymm1,%ymm11
	vpclmulqdq	$0x00,%ymm8,%ymm2,%ymm12
	vpxord	%ymm11,%ymm5,%ymm5
	vpclmulqdq	$0x00,%ymm9,%ymm3,%ymm13
	vpternlogd	$0x96,%ymm13,%ymm12,%ymm5
	vpclmulqdq	$0x01,%ymm6,%ymm0,%ymm11
	vpclmulqdq	$0x01,%ymm7,%ymm1,%ymm12
	vpclmulqdq	$0x01,%ymm8,%ymm2,%ymm13
	vpternlogd	$0x96,%ymm13,%ymm12,%ymm11
	vpclmulqdq	$0x01,%ymm9,%ymm3,%ymm12
	vpclmulqdq	$0x10,%ymm6,%ymm0,%ymm13
	vpternlogd	$0x96,%ymm13,%ymm12,%ymm11
	vpclmulqdq	$0x10,%ymm7,%ymm1,%ymm12
	vpclmulqdq	$0x10,%ymm8,%ymm2,%ymm13
	vpternlogd	$0x96,%ymm13,%ymm12,%ymm11
	vpclmulqdq	$0x01,%ymm5,%ymm10,%ymm13
	vpclmulqdq	$0x10,%ymm9,%ymm3,%ymm12
	vpxord	%ymm12,%ymm11,%ymm11
	vpshufd	$0x4e,%ymm5,%ymm5
	vpclmulqdq	$0x11,%ymm6,%ymm0,%ymm0
	vpclmulqdq	$0x11,%ymm7,%ymm1,%ymm1
	vpclmulqdq	$0x11,%ymm8,%ymm2,%ymm2
	vpternlogd	$0x96,%ymm13,%ymm5,%ymm11
	vpclmulqdq	$0x11,%ymm9,%ymm3,%ymm3
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm0
	vpclmulqdq	$0x01,%ymm11,%ymm10,%ymm12
	vpxord	%ymm3,%ymm0,%ymm5
	vpshufd	$0x4e,%ymm11,%ymm11
	vpternlogd	$0x96,%ymm12,%ymm11,%ymm5
	vextracti32x4	$1,%ymm5,%xmm0
	vpxord	%xmm0,%xmm5,%xmm5

	subq	$-128,%rdx
	addq	$-128,%rcx
	cmpq	$128-1,%rcx
	ja	L$aad_loop_4x__func1


	cmpq	$32,%rcx
	jb	L$aad_large_done__func1
L$aad_loop_1x__func1:
	vmovdqu8	(%rdx),%ymm0
	vpshufb	%ymm4,%ymm0,%ymm0
	vpxord	%ymm0,%ymm5,%ymm5
	vpclmulqdq	$0x00,%ymm9,%ymm5,%ymm0
	vpclmulqdq	$0x01,%ymm9,%ymm5,%ymm1
	vpclmulqdq	$0x10,%ymm9,%ymm5,%ymm2
	vpxord	%ymm2,%ymm1,%ymm1
	vpclmulqdq	$0x01,%ymm0,%ymm10,%ymm2
	vpshufd	$0x4e,%ymm0,%ymm0
	vpternlogd	$0x96,%ymm2,%ymm0,%ymm1
	vpclmulqdq	$0x11,%ymm9,%ymm5,%ymm5
	vpclmulqdq	$0x01,%ymm1,%ymm10,%ymm0
	vpshufd	$0x4e,%ymm1,%ymm1
	vpternlogd	$0x96,%ymm0,%ymm1,%ymm5

	vextracti32x4	$1,%ymm5,%xmm0
	vpxord	%xmm0,%xmm5,%xmm5

	addq	$32,%rdx
	subq	$32,%rcx
	cmpq	$32,%rcx
	jae	L$aad_loop_1x__func1

L$aad_large_done__func1:


	vzeroupper


L$aad_blockbyblock__func1:
	testq	%rcx,%rcx
	jz	L$aad_done__func1
	vmovdqu	256-16(%rsi),%xmm9
L$aad_loop_blockbyblock__func1:
	vmovdqu	(%rdx),%xmm0
	vpshufb	%xmm4,%xmm0,%xmm0
	vpxor	%xmm0,%xmm5,%xmm5
	vpclmulqdq	$0x00,%xmm9,%xmm5,%xmm0
	vpclmulqdq	$0x01,%xmm9,%xmm5,%xmm1
	vpclmulqdq	$0x10,%xmm9,%xmm5,%xmm2
	vpxord	%xmm2,%xmm1,%xmm1
	vpclmulqdq	$0x01,%xmm0,%xmm10,%xmm2
	vpshufd	$0x4e,%xmm0,%xmm0
	vpternlogd	$0x96,%xmm2,%xmm0,%xmm1
	vpclmulqdq	$0x11,%xmm9,%xmm5,%xmm5
	vpclmulqdq	$0x01,%xmm1,%xmm10,%xmm0
	vpshufd	$0x4e,%xmm1,%xmm1
	vpternlogd	$0x96,%xmm0,%xmm1,%xmm5

	addq	$16,%rdx
	subq	$16,%rcx
	jnz	L$aad_loop_blockbyblock__func1

L$aad_done__func1:

	vpshufb	%xmm4,%xmm5,%xmm5
	vmovdqu	%xmm5,(%rdi)
	ret



.globl	_aes_gcm_enc_update_vaes_avx10_256
.private_extern _aes_gcm_enc_update_vaes_avx10_256

.p2align	5
_aes_gcm_enc_update_vaes_avx10_256:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12
#ifdef BORINGSSL_DISPATCH_TEST

	movb	$1,_BORINGSSL_function_hit+6(%rip)
#endif

	vbroadcasti32x4	L$bswap_mask(%rip),%ymm8
	vbroadcasti32x4	L$gfpoly(%rip),%ymm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%ymm12
	vpshufb	%ymm8,%ymm12,%ymm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%ymm13
	vbroadcasti32x4	(%r11),%ymm14


	vpaddd	L$ctr_pattern(%rip),%ymm12,%ymm12


	vbroadcasti32x4	L$inc_2blocks(%rip),%ymm11



	cmpq	$128-1,%rdx
	jbe	L$crypt_loop_4x_done__func1


	vmovdqu8	256-128(%r9),%ymm27
	vmovdqu8	256-96(%r9),%ymm28
	vmovdqu8	256-64(%r9),%ymm29
	vmovdqu8	256-32(%r9),%ymm30




	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm1
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm2
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm3
	vpaddd	%ymm11,%ymm12,%ymm12


	vpxord	%ymm13,%ymm0,%ymm0
	vpxord	%ymm13,%ymm1,%ymm1
	vpxord	%ymm13,%ymm2,%ymm2
	vpxord	%ymm13,%ymm3,%ymm3

	leaq	16(%rcx),%rax
L$vaesenc_loop_first_4_vecs__func1:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_first_4_vecs__func1



	vpxord	0(%rdi),%ymm14,%ymm4
	vpxord	32(%rdi),%ymm14,%ymm5
	vpxord	64(%rdi),%ymm14,%ymm6
	vpxord	96(%rdi),%ymm14,%ymm7



	vaesenclast	%ymm4,%ymm0,%ymm4
	vaesenclast	%ymm5,%ymm1,%ymm5
	vaesenclast	%ymm6,%ymm2,%ymm6
	vaesenclast	%ymm7,%ymm3,%ymm7


	vmovdqu8	%ymm4,0(%rsi)
	vmovdqu8	%ymm5,32(%rsi)
	vmovdqu8	%ymm6,64(%rsi)
	vmovdqu8	%ymm7,96(%rsi)

	subq	$-128,%rdi
	subq	$-128,%rsi
	addq	$-128,%rdx
	cmpq	$128-1,%rdx
	jbe	L$ghash_last_ciphertext_4x__func1
	vbroadcasti32x4	-144(%r11),%ymm15
	vbroadcasti32x4	-128(%r11),%ymm16
	vbroadcasti32x4	-112(%r11),%ymm17
	vbroadcasti32x4	-96(%r11),%ymm18
	vbroadcasti32x4	-80(%r11),%ymm19
	vbroadcasti32x4	-64(%r11),%ymm20
	vbroadcasti32x4	-48(%r11),%ymm21
	vbroadcasti32x4	-32(%r11),%ymm22
	vbroadcasti32x4	-16(%r11),%ymm23
L$crypt_loop_4x__func1:



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm1
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm2
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm3
	vpaddd	%ymm11,%ymm12,%ymm12


	vpxord	%ymm13,%ymm0,%ymm0
	vpxord	%ymm13,%ymm1,%ymm1
	vpxord	%ymm13,%ymm2,%ymm2
	vpxord	%ymm13,%ymm3,%ymm3

	cmpl	$24,%r10d
	jl	L$aes128__func1
	je	L$aes192__func1

	vbroadcasti32x4	-208(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-192(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes192__func1:
	vbroadcasti32x4	-176(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-160(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes128__func1:
	vpshufb	%ymm8,%ymm4,%ymm4
	vpxord	%ymm10,%ymm4,%ymm4
	vpshufb	%ymm8,%ymm5,%ymm5
	vpshufb	%ymm8,%ymm6,%ymm6

	vaesenc	%ymm15,%ymm0,%ymm0
	vaesenc	%ymm15,%ymm1,%ymm1
	vaesenc	%ymm15,%ymm2,%ymm2
	vaesenc	%ymm15,%ymm3,%ymm3

	vpshufb	%ymm8,%ymm7,%ymm7
	vpclmulqdq	$0x00,%ymm27,%ymm4,%ymm10
	vpclmulqdq	$0x00,%ymm28,%ymm5,%ymm24
	vpclmulqdq	$0x00,%ymm29,%ymm6,%ymm25

	vaesenc	%ymm16,%ymm0,%ymm0
	vaesenc	%ymm16,%ymm1,%ymm1
	vaesenc	%ymm16,%ymm2,%ymm2
	vaesenc	%ymm16,%ymm3,%ymm3

	vpxord	%ymm24,%ymm10,%ymm10
	vpclmulqdq	$0x00,%ymm30,%ymm7,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm10
	vpclmulqdq	$0x01,%ymm27,%ymm4,%ymm24

	vaesenc	%ymm17,%ymm0,%ymm0
	vaesenc	%ymm17,%ymm1,%ymm1
	vaesenc	%ymm17,%ymm2,%ymm2
	vaesenc	%ymm17,%ymm3,%ymm3

	vpclmulqdq	$0x01,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x01,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm30,%ymm7,%ymm25

	vaesenc	%ymm18,%ymm0,%ymm0
	vaesenc	%ymm18,%ymm1,%ymm1
	vaesenc	%ymm18,%ymm2,%ymm2
	vaesenc	%ymm18,%ymm3,%ymm3

	vpclmulqdq	$0x10,%ymm27,%ymm4,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x10,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x10,%ymm29,%ymm6,%ymm26

	vaesenc	%ymm19,%ymm0,%ymm0
	vaesenc	%ymm19,%ymm1,%ymm1
	vaesenc	%ymm19,%ymm2,%ymm2
	vaesenc	%ymm19,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm10,%ymm31,%ymm26
	vpclmulqdq	$0x10,%ymm30,%ymm7,%ymm25
	vpxord	%ymm25,%ymm24,%ymm24

	vaesenc	%ymm20,%ymm0,%ymm0
	vaesenc	%ymm20,%ymm1,%ymm1
	vaesenc	%ymm20,%ymm2,%ymm2
	vaesenc	%ymm20,%ymm3,%ymm3

	vpshufd	$0x4e,%ymm10,%ymm10
	vpclmulqdq	$0x11,%ymm27,%ymm4,%ymm4
	vpclmulqdq	$0x11,%ymm28,%ymm5,%ymm5
	vpclmulqdq	$0x11,%ymm29,%ymm6,%ymm6

	vaesenc	%ymm21,%ymm0,%ymm0
	vaesenc	%ymm21,%ymm1,%ymm1
	vaesenc	%ymm21,%ymm2,%ymm2
	vaesenc	%ymm21,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm10,%ymm24
	vpclmulqdq	$0x11,%ymm30,%ymm7,%ymm7
	vpternlogd	$0x96,%ymm6,%ymm5,%ymm4
	vpclmulqdq	$0x01,%ymm24,%ymm31,%ymm25

	vaesenc	%ymm22,%ymm0,%ymm0
	vaesenc	%ymm22,%ymm1,%ymm1
	vaesenc	%ymm22,%ymm2,%ymm2
	vaesenc	%ymm22,%ymm3,%ymm3

	vpxord	%ymm7,%ymm4,%ymm10
	vpshufd	$0x4e,%ymm24,%ymm24
	vpternlogd	$0x96,%ymm25,%ymm24,%ymm10

	vaesenc	%ymm23,%ymm0,%ymm0
	vaesenc	%ymm23,%ymm1,%ymm1
	vaesenc	%ymm23,%ymm2,%ymm2
	vaesenc	%ymm23,%ymm3,%ymm3

	vextracti32x4	$1,%ymm10,%xmm4
	vpxord	%xmm4,%xmm10,%xmm10




	vpxord	0(%rdi),%ymm14,%ymm4
	vpxord	32(%rdi),%ymm14,%ymm5
	vpxord	64(%rdi),%ymm14,%ymm6
	vpxord	96(%rdi),%ymm14,%ymm7



	vaesenclast	%ymm4,%ymm0,%ymm4
	vaesenclast	%ymm5,%ymm1,%ymm5
	vaesenclast	%ymm6,%ymm2,%ymm6
	vaesenclast	%ymm7,%ymm3,%ymm7


	vmovdqu8	%ymm4,0(%rsi)
	vmovdqu8	%ymm5,32(%rsi)
	vmovdqu8	%ymm6,64(%rsi)
	vmovdqu8	%ymm7,96(%rsi)

	subq	$-128,%rdi
	subq	$-128,%rsi
	addq	$-128,%rdx
	cmpq	$128-1,%rdx
	ja	L$crypt_loop_4x__func1
L$ghash_last_ciphertext_4x__func1:
	vpshufb	%ymm8,%ymm4,%ymm4
	vpxord	%ymm10,%ymm4,%ymm4
	vpshufb	%ymm8,%ymm5,%ymm5
	vpshufb	%ymm8,%ymm6,%ymm6
	vpshufb	%ymm8,%ymm7,%ymm7
	vpclmulqdq	$0x00,%ymm27,%ymm4,%ymm10
	vpclmulqdq	$0x00,%ymm28,%ymm5,%ymm24
	vpclmulqdq	$0x00,%ymm29,%ymm6,%ymm25
	vpxord	%ymm24,%ymm10,%ymm10
	vpclmulqdq	$0x00,%ymm30,%ymm7,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm10
	vpclmulqdq	$0x01,%ymm27,%ymm4,%ymm24
	vpclmulqdq	$0x01,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x01,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm30,%ymm7,%ymm25
	vpclmulqdq	$0x10,%ymm27,%ymm4,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x10,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x10,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm10,%ymm31,%ymm26
	vpclmulqdq	$0x10,%ymm30,%ymm7,%ymm25
	vpxord	%ymm25,%ymm24,%ymm24
	vpshufd	$0x4e,%ymm10,%ymm10
	vpclmulqdq	$0x11,%ymm27,%ymm4,%ymm4
	vpclmulqdq	$0x11,%ymm28,%ymm5,%ymm5
	vpclmulqdq	$0x11,%ymm29,%ymm6,%ymm6
	vpternlogd	$0x96,%ymm26,%ymm10,%ymm24
	vpclmulqdq	$0x11,%ymm30,%ymm7,%ymm7
	vpternlogd	$0x96,%ymm6,%ymm5,%ymm4
	vpclmulqdq	$0x01,%ymm24,%ymm31,%ymm25
	vpxord	%ymm7,%ymm4,%ymm10
	vpshufd	$0x4e,%ymm24,%ymm24
	vpternlogd	$0x96,%ymm25,%ymm24,%ymm10
	vextracti32x4	$1,%ymm10,%xmm4
	vpxord	%xmm4,%xmm10,%xmm10

L$crypt_loop_4x_done__func1:

	testq	%rdx,%rdx
	jz	L$done__func1




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$32,%rdx
	jb	L$partial_vec__func1

L$crypt_loop_1x__func1:



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_full_vec__func1:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_full_vec__func1
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi)


	vmovdqu8	(%r8),%ymm30
	vpshufb	%ymm8,%ymm0,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$32,%r8
	addq	$32,%rdi
	addq	$32,%rsi
	subq	$32,%rdx
	cmpq	$32,%rdx
	jae	L$crypt_loop_1x__func1

	testq	%rdx,%rdx
	jz	L$reduce__func1

L$partial_vec__func1:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k2



	vpshufb	%ymm8,%ymm12,%ymm0
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_partialvec__func1:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_partialvec__func1
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1{%k1}{z}
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi){%k1}













	vmovdqu8	(%r8),%ymm30{%k2}{z}
	vmovdqu8	%ymm0,%ymm1{%k1}{z}
	vpshufb	%ymm8,%ymm1,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6


L$reduce__func1:

	vpclmulqdq	$0x01,%ymm4,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm0,%ymm4,%ymm5
	vpclmulqdq	$0x01,%ymm5,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm5,%ymm5
	vpternlogd	$0x96,%ymm0,%ymm5,%ymm6

	vextracti32x4	$1,%ymm6,%xmm0
	vpxord	%xmm0,%xmm6,%xmm10


L$done__func1:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



.globl	_aes_gcm_dec_update_vaes_avx10_256
.private_extern _aes_gcm_dec_update_vaes_avx10_256

.p2align	5
_aes_gcm_dec_update_vaes_avx10_256:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12

	vbroadcasti32x4	L$bswap_mask(%rip),%ymm8
	vbroadcasti32x4	L$gfpoly(%rip),%ymm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%ymm12
	vpshufb	%ymm8,%ymm12,%ymm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%ymm13
	vbroadcasti32x4	(%r11),%ymm14


	vpaddd	L$ctr_pattern(%rip),%ymm12,%ymm12


	vbroadcasti32x4	L$inc_2blocks(%rip),%ymm11



	cmpq	$128-1,%rdx
	jbe	L$crypt_loop_4x_done__func2


	vmovdqu8	256-128(%r9),%ymm27
	vmovdqu8	256-96(%r9),%ymm28
	vmovdqu8	256-64(%r9),%ymm29
	vmovdqu8	256-32(%r9),%ymm30
	vbroadcasti32x4	-144(%r11),%ymm15
	vbroadcasti32x4	-128(%r11),%ymm16
	vbroadcasti32x4	-112(%r11),%ymm17
	vbroadcasti32x4	-96(%r11),%ymm18
	vbroadcasti32x4	-80(%r11),%ymm19
	vbroadcasti32x4	-64(%r11),%ymm20
	vbroadcasti32x4	-48(%r11),%ymm21
	vbroadcasti32x4	-32(%r11),%ymm22
	vbroadcasti32x4	-16(%r11),%ymm23
L$crypt_loop_4x__func2:
	vmovdqu8	0(%rdi),%ymm4
	vmovdqu8	32(%rdi),%ymm5
	vmovdqu8	64(%rdi),%ymm6
	vmovdqu8	96(%rdi),%ymm7



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm1
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm2
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm3
	vpaddd	%ymm11,%ymm12,%ymm12


	vpxord	%ymm13,%ymm0,%ymm0
	vpxord	%ymm13,%ymm1,%ymm1
	vpxord	%ymm13,%ymm2,%ymm2
	vpxord	%ymm13,%ymm3,%ymm3

	cmpl	$24,%r10d
	jl	L$aes128__func2
	je	L$aes192__func2

	vbroadcasti32x4	-208(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-192(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes192__func2:
	vbroadcasti32x4	-176(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-160(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes128__func2:
	vpshufb	%ymm8,%ymm4,%ymm4
	vpxord	%ymm10,%ymm4,%ymm4
	vpshufb	%ymm8,%ymm5,%ymm5
	vpshufb	%ymm8,%ymm6,%ymm6

	vaesenc	%ymm15,%ymm0,%ymm0
	vaesenc	%ymm15,%ymm1,%ymm1
	vaesenc	%ymm15,%ymm2,%ymm2
	vaesenc	%ymm15,%ymm3,%ymm3

	vpshufb	%ymm8,%ymm7,%ymm7
	vpclmulqdq	$0x00,%ymm27,%ymm4,%ymm10
	vpclmulqdq	$0x00,%ymm28,%ymm5,%ymm24
	vpclmulqdq	$0x00,%ymm29,%ymm6,%ymm25

	vaesenc	%ymm16,%ymm0,%ymm0
	vaesenc	%ymm16,%ymm1,%ymm1
	vaesenc	%ymm16,%ymm2,%ymm2
	vaesenc	%ymm16,%ymm3,%ymm3

	vpxord	%ymm24,%ymm10,%ymm10
	vpclmulqdq	$0x00,%ymm30,%ymm7,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm10
	vpclmulqdq	$0x01,%ymm27,%ymm4,%ymm24

	vaesenc	%ymm17,%ymm0,%ymm0
	vaesenc	%ymm17,%ymm1,%ymm1
	vaesenc	%ymm17,%ymm2,%ymm2
	vaesenc	%ymm17,%ymm3,%ymm3

	vpclmulqdq	$0x01,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x01,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm30,%ymm7,%ymm25

	vaesenc	%ymm18,%ymm0,%ymm0
	vaesenc	%ymm18,%ymm1,%ymm1
	vaesenc	%ymm18,%ymm2,%ymm2
	vaesenc	%ymm18,%ymm3,%ymm3

	vpclmulqdq	$0x10,%ymm27,%ymm4,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x10,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x10,%ymm29,%ymm6,%ymm26

	vaesenc	%ymm19,%ymm0,%ymm0
	vaesenc	%ymm19,%ymm1,%ymm1
	vaesenc	%ymm19,%ymm2,%ymm2
	vaesenc	%ymm19,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm10,%ymm31,%ymm26
	vpclmulqdq	$0x10,%ymm30,%ymm7,%ymm25
	vpxord	%ymm25,%ymm24,%ymm24

	vaesenc	%ymm20,%ymm0,%ymm0
	vaesenc	%ymm20,%ymm1,%ymm1
	vaesenc	%ymm20,%ymm2,%ymm2
	vaesenc	%ymm20,%ymm3,%ymm3

	vpshufd	$0x4e,%ymm10,%ymm10
	vpclmulqdq	$0x11,%ymm27,%ymm4,%ymm4
	vpclmulqdq	$0x11,%ymm28,%ymm5,%ymm5
	vpclmulqdq	$0x11,%ymm29,%ymm6,%ymm6

	vaesenc	%ymm21,%ymm0,%ymm0
	vaesenc	%ymm21,%ymm1,%ymm1
	vaesenc	%ymm21,%ymm2,%ymm2
	vaesenc	%ymm21,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm10,%ymm24
	vpclmulqdq	$0x11,%ymm30,%ymm7,%ymm7
	vpternlogd	$0x96,%ymm6,%ymm5,%ymm4
	vpclmulqdq	$0x01,%ymm24,%ymm31,%ymm25

	vaesenc	%ymm22,%ymm0,%ymm0
	vaesenc	%ymm22,%ymm1,%ymm1
	vaesenc	%ymm22,%ymm2,%ymm2
	vaesenc	%ymm22,%ymm3,%ymm3

	vpxord	%ymm7,%ymm4,%ymm10
	vpshufd	$0x4e,%ymm24,%ymm24
	vpternlogd	$0x96,%ymm25,%ymm24,%ymm10

	vaesenc	%ymm23,%ymm0,%ymm0
	vaesenc	%ymm23,%ymm1,%ymm1
	vaesenc	%ymm23,%ymm2,%ymm2
	vaesenc	%ymm23,%ymm3,%ymm3

	vextracti32x4	$1,%ymm10,%xmm4
	vpxord	%xmm4,%xmm10,%xmm10




	vpxord	0(%rdi),%ymm14,%ymm4
	vpxord	32(%rdi),%ymm14,%ymm5
	vpxord	64(%rdi),%ymm14,%ymm6
	vpxord	96(%rdi),%ymm14,%ymm7



	vaesenclast	%ymm4,%ymm0,%ymm4
	vaesenclast	%ymm5,%ymm1,%ymm5
	vaesenclast	%ymm6,%ymm2,%ymm6
	vaesenclast	%ymm7,%ymm3,%ymm7


	vmovdqu8	%ymm4,0(%rsi)
	vmovdqu8	%ymm5,32(%rsi)
	vmovdqu8	%ymm6,64(%rsi)
	vmovdqu8	%ymm7,96(%rsi)

	subq	$-128,%rdi
	subq	$-128,%rsi
	addq	$-128,%rdx
	cmpq	$128-1,%rdx
	ja	L$crypt_loop_4x__func2
L$crypt_loop_4x_done__func2:

	testq	%rdx,%rdx
	jz	L$done__func2




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$32,%rdx
	jb	L$partial_vec__func2

L$crypt_loop_1x__func2:



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_full_vec__func2:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_full_vec__func2
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi)


	vmovdqu8	(%r8),%ymm30
	vpshufb	%ymm8,%ymm1,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$32,%r8
	addq	$32,%rdi
	addq	$32,%rsi
	subq	$32,%rdx
	cmpq	$32,%rdx
	jae	L$crypt_loop_1x__func2

	testq	%rdx,%rdx
	jz	L$reduce__func2

L$partial_vec__func2:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k2



	vpshufb	%ymm8,%ymm12,%ymm0
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_partialvec__func2:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_partialvec__func2
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1{%k1}{z}
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi){%k1}













	vmovdqu8	(%r8),%ymm30{%k2}{z}

	vpshufb	%ymm8,%ymm1,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6


L$reduce__func2:

	vpclmulqdq	$0x01,%ymm4,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm0,%ymm4,%ymm5
	vpclmulqdq	$0x01,%ymm5,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm5,%ymm5
	vpternlogd	$0x96,%ymm0,%ymm5,%ymm6

	vextracti32x4	$1,%ymm6,%xmm0
	vpxord	%xmm0,%xmm6,%xmm10


L$done__func2:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



.globl	_gcm_ghash_vpclmulqdq_avx10_512
.private_extern _gcm_ghash_vpclmulqdq_avx10_512

.p2align	5
_gcm_ghash_vpclmulqdq_avx10_512:


_CET_ENDBR






	vmovdqu	L$bswap_mask(%rip),%xmm4
	vmovdqu	L$gfpoly(%rip),%xmm10


	vmovdqu	(%rdi),%xmm5
	vpshufb	%xmm4,%xmm5,%xmm5


	cmpq	$64,%rcx
	jb	L$aad_blockbyblock__func2



	vshufi64x2	$0,%zmm4,%zmm4,%zmm4
	vshufi64x2	$0,%zmm10,%zmm10,%zmm10


	vmovdqu8	256-64(%rsi),%zmm9

	cmpq	$256-1,%rcx
	jbe	L$aad_loop_1x__func2


	vmovdqu8	256-256(%rsi),%zmm6
	vmovdqu8	256-192(%rsi),%zmm7
	vmovdqu8	256-128(%rsi),%zmm8


L$aad_loop_4x__func2:
	vmovdqu8	0(%rdx),%zmm0
	vmovdqu8	64(%rdx),%zmm1
	vmovdqu8	128(%rdx),%zmm2
	vmovdqu8	192(%rdx),%zmm3
	vpshufb	%zmm4,%zmm0,%zmm0
	vpxord	%zmm5,%zmm0,%zmm0
	vpshufb	%zmm4,%zmm1,%zmm1
	vpshufb	%zmm4,%zmm2,%zmm2
	vpshufb	%zmm4,%zmm3,%zmm3
	vpclmulqdq	$0x00,%zmm6,%zmm0,%zmm5
	vpclmulqdq	$0x00,%zmm7,%zmm1,%zmm11
	vpclmulqdq	$0x00,%zmm8,%zmm2,%zmm12
	vpxord	%zmm11,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm9,%zmm3,%zmm13
	vpternlogd	$0x96,%zmm13,%zmm12,%zmm5
	vpclmulqdq	$0x01,%zmm6,%zmm0,%zmm11
	vpclmulqdq	$0x01,%zmm7,%zmm1,%zmm12
	vpclmulqdq	$0x01,%zmm8,%zmm2,%zmm13
	vpternlogd	$0x96,%zmm13,%zmm12,%zmm11
	vpclmulqdq	$0x01,%zmm9,%zmm3,%zmm12
	vpclmulqdq	$0x10,%zmm6,%zmm0,%zmm13
	vpternlogd	$0x96,%zmm13,%zmm12,%zmm11
	vpclmulqdq	$0x10,%zmm7,%zmm1,%zmm12
	vpclmulqdq	$0x10,%zmm8,%zmm2,%zmm13
	vpternlogd	$0x96,%zmm13,%zmm12,%zmm11
	vpclmulqdq	$0x01,%zmm5,%zmm10,%zmm13
	vpclmulqdq	$0x10,%zmm9,%zmm3,%zmm12
	vpxord	%zmm12,%zmm11,%zmm11
	vpshufd	$0x4e,%zmm5,%zmm5
	vpclmulqdq	$0x11,%zmm6,%zmm0,%zmm0
	vpclmulqdq	$0x11,%zmm7,%zmm1,%zmm1
	vpclmulqdq	$0x11,%zmm8,%zmm2,%zmm2
	vpternlogd	$0x96,%zmm13,%zmm5,%zmm11
	vpclmulqdq	$0x11,%zmm9,%zmm3,%zmm3
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm0
	vpclmulqdq	$0x01,%zmm11,%zmm10,%zmm12
	vpxord	%zmm3,%zmm0,%zmm5
	vpshufd	$0x4e,%zmm11,%zmm11
	vpternlogd	$0x96,%zmm12,%zmm11,%zmm5
	vextracti32x4	$1,%zmm5,%xmm0
	vextracti32x4	$2,%zmm5,%xmm1
	vextracti32x4	$3,%zmm5,%xmm2
	vpxord	%xmm0,%xmm5,%xmm5
	vpternlogd	$0x96,%xmm1,%xmm2,%xmm5

	subq	$-256,%rdx
	addq	$-256,%rcx
	cmpq	$256-1,%rcx
	ja	L$aad_loop_4x__func2


	cmpq	$64,%rcx
	jb	L$aad_large_done__func2
L$aad_loop_1x__func2:
	vmovdqu8	(%rdx),%zmm0
	vpshufb	%zmm4,%zmm0,%zmm0
	vpxord	%zmm0,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm9,%zmm5,%zmm0
	vpclmulqdq	$0x01,%zmm9,%zmm5,%zmm1
	vpclmulqdq	$0x10,%zmm9,%zmm5,%zmm2
	vpxord	%zmm2,%zmm1,%zmm1
	vpclmulqdq	$0x01,%zmm0,%zmm10,%zmm2
	vpshufd	$0x4e,%zmm0,%zmm0
	vpternlogd	$0x96,%zmm2,%zmm0,%zmm1
	vpclmulqdq	$0x11,%zmm9,%zmm5,%zmm5
	vpclmulqdq	$0x01,%zmm1,%zmm10,%zmm0
	vpshufd	$0x4e,%zmm1,%zmm1
	vpternlogd	$0x96,%zmm0,%zmm1,%zmm5

	vextracti32x4	$1,%zmm5,%xmm0
	vextracti32x4	$2,%zmm5,%xmm1
	vextracti32x4	$3,%zmm5,%xmm2
	vpxord	%xmm0,%xmm5,%xmm5
	vpternlogd	$0x96,%xmm1,%xmm2,%xmm5

	addq	$64,%rdx
	subq	$64,%rcx
	cmpq	$64,%rcx
	jae	L$aad_loop_1x__func2

L$aad_large_done__func2:


	vzeroupper


L$aad_blockbyblock__func2:
	testq	%rcx,%rcx
	jz	L$aad_done__func2
	vmovdqu	256-16(%rsi),%xmm9
L$aad_loop_blockbyblock__func2:
	vmovdqu	(%rdx),%xmm0
	vpshufb	%xmm4,%xmm0,%xmm0
	vpxor	%xmm0,%xmm5,%xmm5
	vpclmulqdq	$0x00,%xmm9,%xmm5,%xmm0
	vpclmulqdq	$0x01,%xmm9,%xmm5,%xmm1
	vpclmulqdq	$0x10,%xmm9,%xmm5,%xmm2
	vpxord	%xmm2,%xmm1,%xmm1
	vpclmulqdq	$0x01,%xmm0,%xmm10,%xmm2
	vpshufd	$0x4e,%xmm0,%xmm0
	vpternlogd	$0x96,%xmm2,%xmm0,%xmm1
	vpclmulqdq	$0x11,%xmm9,%xmm5,%xmm5
	vpclmulqdq	$0x01,%xmm1,%xmm10,%xmm0
	vpshufd	$0x4e,%xmm1,%xmm1
	vpternlogd	$0x96,%xmm0,%xmm1,%xmm5

	addq	$16,%rdx
	subq	$16,%rcx
	jnz	L$aad_loop_blockbyblock__func2

L$aad_done__func2:

	vpshufb	%xmm4,%xmm5,%xmm5
	vmovdqu	%xmm5,(%rdi)
	ret



.globl	_aes_gcm_enc_update_vaes_avx10_512
.private_extern _aes_gcm_enc_update_vaes_avx10_512

.p2align	5
_aes_gcm_enc_update_vaes_avx10_512:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12
#ifdef BORINGSSL_DISPATCH_TEST

	movb	$1,_BORINGSSL_function_hit+7(%rip)
#endif

	vbroadcasti32x4	L$bswap_mask(%rip),%zmm8
	vbroadcasti32x4	L$gfpoly(%rip),%zmm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%zmm12
	vpshufb	%zmm8,%zmm12,%zmm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%zmm13
	vbroadcasti32x4	(%r11),%zmm14


	vpaddd	L$ctr_pattern(%rip),%zmm12,%zmm12


	vbroadcasti32x4	L$inc_4blocks(%rip),%zmm11



	cmpq	$256-1,%rdx
	jbe	L$crypt_loop_4x_done__func3


	vmovdqu8	256-256(%r9),%zmm27
	vmovdqu8	256-192(%r9),%zmm28
	vmovdqu8	256-128(%r9),%zmm29
	vmovdqu8	256-64(%r9),%zmm30




	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm1
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm2
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm3
	vpaddd	%zmm11,%zmm12,%zmm12


	vpxord	%zmm13,%zmm0,%zmm0
	vpxord	%zmm13,%zmm1,%zmm1
	vpxord	%zmm13,%zmm2,%zmm2
	vpxord	%zmm13,%zmm3,%zmm3

	leaq	16(%rcx),%rax
L$vaesenc_loop_first_4_vecs__func3:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_first_4_vecs__func3



	vpxord	0(%rdi),%zmm14,%zmm4
	vpxord	64(%rdi),%zmm14,%zmm5
	vpxord	128(%rdi),%zmm14,%zmm6
	vpxord	192(%rdi),%zmm14,%zmm7



	vaesenclast	%zmm4,%zmm0,%zmm4
	vaesenclast	%zmm5,%zmm1,%zmm5
	vaesenclast	%zmm6,%zmm2,%zmm6
	vaesenclast	%zmm7,%zmm3,%zmm7


	vmovdqu8	%zmm4,0(%rsi)
	vmovdqu8	%zmm5,64(%rsi)
	vmovdqu8	%zmm6,128(%rsi)
	vmovdqu8	%zmm7,192(%rsi)

	subq	$-256,%rdi
	subq	$-256,%rsi
	addq	$-256,%rdx
	cmpq	$256-1,%rdx
	jbe	L$ghash_last_ciphertext_4x__func3
	vbroadcasti32x4	-144(%r11),%zmm15
	vbroadcasti32x4	-128(%r11),%zmm16
	vbroadcasti32x4	-112(%r11),%zmm17
	vbroadcasti32x4	-96(%r11),%zmm18
	vbroadcasti32x4	-80(%r11),%zmm19
	vbroadcasti32x4	-64(%r11),%zmm20
	vbroadcasti32x4	-48(%r11),%zmm21
	vbroadcasti32x4	-32(%r11),%zmm22
	vbroadcasti32x4	-16(%r11),%zmm23
L$crypt_loop_4x__func3:



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm1
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm2
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm3
	vpaddd	%zmm11,%zmm12,%zmm12


	vpxord	%zmm13,%zmm0,%zmm0
	vpxord	%zmm13,%zmm1,%zmm1
	vpxord	%zmm13,%zmm2,%zmm2
	vpxord	%zmm13,%zmm3,%zmm3

	cmpl	$24,%r10d
	jl	L$aes128__func3
	je	L$aes192__func3

	vbroadcasti32x4	-208(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-192(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes192__func3:
	vbroadcasti32x4	-176(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-160(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes128__func3:
	vpshufb	%zmm8,%zmm4,%zmm4
	vpxord	%zmm10,%zmm4,%zmm4
	vpshufb	%zmm8,%zmm5,%zmm5
	vpshufb	%zmm8,%zmm6,%zmm6

	vaesenc	%zmm15,%zmm0,%zmm0
	vaesenc	%zmm15,%zmm1,%zmm1
	vaesenc	%zmm15,%zmm2,%zmm2
	vaesenc	%zmm15,%zmm3,%zmm3

	vpshufb	%zmm8,%zmm7,%zmm7
	vpclmulqdq	$0x00,%zmm27,%zmm4,%zmm10
	vpclmulqdq	$0x00,%zmm28,%zmm5,%zmm24
	vpclmulqdq	$0x00,%zmm29,%zmm6,%zmm25

	vaesenc	%zmm16,%zmm0,%zmm0
	vaesenc	%zmm16,%zmm1,%zmm1
	vaesenc	%zmm16,%zmm2,%zmm2
	vaesenc	%zmm16,%zmm3,%zmm3

	vpxord	%zmm24,%zmm10,%zmm10
	vpclmulqdq	$0x00,%zmm30,%zmm7,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm10
	vpclmulqdq	$0x01,%zmm27,%zmm4,%zmm24

	vaesenc	%zmm17,%zmm0,%zmm0
	vaesenc	%zmm17,%zmm1,%zmm1
	vaesenc	%zmm17,%zmm2,%zmm2
	vaesenc	%zmm17,%zmm3,%zmm3

	vpclmulqdq	$0x01,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x01,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm30,%zmm7,%zmm25

	vaesenc	%zmm18,%zmm0,%zmm0
	vaesenc	%zmm18,%zmm1,%zmm1
	vaesenc	%zmm18,%zmm2,%zmm2
	vaesenc	%zmm18,%zmm3,%zmm3

	vpclmulqdq	$0x10,%zmm27,%zmm4,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x10,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x10,%zmm29,%zmm6,%zmm26

	vaesenc	%zmm19,%zmm0,%zmm0
	vaesenc	%zmm19,%zmm1,%zmm1
	vaesenc	%zmm19,%zmm2,%zmm2
	vaesenc	%zmm19,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm10,%zmm31,%zmm26
	vpclmulqdq	$0x10,%zmm30,%zmm7,%zmm25
	vpxord	%zmm25,%zmm24,%zmm24

	vaesenc	%zmm20,%zmm0,%zmm0
	vaesenc	%zmm20,%zmm1,%zmm1
	vaesenc	%zmm20,%zmm2,%zmm2
	vaesenc	%zmm20,%zmm3,%zmm3

	vpshufd	$0x4e,%zmm10,%zmm10
	vpclmulqdq	$0x11,%zmm27,%zmm4,%zmm4
	vpclmulqdq	$0x11,%zmm28,%zmm5,%zmm5
	vpclmulqdq	$0x11,%zmm29,%zmm6,%zmm6

	vaesenc	%zmm21,%zmm0,%zmm0
	vaesenc	%zmm21,%zmm1,%zmm1
	vaesenc	%zmm21,%zmm2,%zmm2
	vaesenc	%zmm21,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm10,%zmm24
	vpclmulqdq	$0x11,%zmm30,%zmm7,%zmm7
	vpternlogd	$0x96,%zmm6,%zmm5,%zmm4
	vpclmulqdq	$0x01,%zmm24,%zmm31,%zmm25

	vaesenc	%zmm22,%zmm0,%zmm0
	vaesenc	%zmm22,%zmm1,%zmm1
	vaesenc	%zmm22,%zmm2,%zmm2
	vaesenc	%zmm22,%zmm3,%zmm3

	vpxord	%zmm7,%zmm4,%zmm10
	vpshufd	$0x4e,%zmm24,%zmm24
	vpternlogd	$0x96,%zmm25,%zmm24,%zmm10

	vaesenc	%zmm23,%zmm0,%zmm0
	vaesenc	%zmm23,%zmm1,%zmm1
	vaesenc	%zmm23,%zmm2,%zmm2
	vaesenc	%zmm23,%zmm3,%zmm3

	vextracti32x4	$1,%zmm10,%xmm4
	vextracti32x4	$2,%zmm10,%xmm5
	vextracti32x4	$3,%zmm10,%xmm6
	vpxord	%xmm4,%xmm10,%xmm10
	vpternlogd	$0x96,%xmm5,%xmm6,%xmm10




	vpxord	0(%rdi),%zmm14,%zmm4
	vpxord	64(%rdi),%zmm14,%zmm5
	vpxord	128(%rdi),%zmm14,%zmm6
	vpxord	192(%rdi),%zmm14,%zmm7



	vaesenclast	%zmm4,%zmm0,%zmm4
	vaesenclast	%zmm5,%zmm1,%zmm5
	vaesenclast	%zmm6,%zmm2,%zmm6
	vaesenclast	%zmm7,%zmm3,%zmm7


	vmovdqu8	%zmm4,0(%rsi)
	vmovdqu8	%zmm5,64(%rsi)
	vmovdqu8	%zmm6,128(%rsi)
	vmovdqu8	%zmm7,192(%rsi)

	subq	$-256,%rdi
	subq	$-256,%rsi
	addq	$-256,%rdx
	cmpq	$256-1,%rdx
	ja	L$crypt_loop_4x__func3
L$ghash_last_ciphertext_4x__func3:
	vpshufb	%zmm8,%zmm4,%zmm4
	vpxord	%zmm10,%zmm4,%zmm4
	vpshufb	%zmm8,%zmm5,%zmm5
	vpshufb	%zmm8,%zmm6,%zmm6
	vpshufb	%zmm8,%zmm7,%zmm7
	vpclmulqdq	$0x00,%zmm27,%zmm4,%zmm10
	vpclmulqdq	$0x00,%zmm28,%zmm5,%zmm24
	vpclmulqdq	$0x00,%zmm29,%zmm6,%zmm25
	vpxord	%zmm24,%zmm10,%zmm10
	vpclmulqdq	$0x00,%zmm30,%zmm7,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm10
	vpclmulqdq	$0x01,%zmm27,%zmm4,%zmm24
	vpclmulqdq	$0x01,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x01,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm30,%zmm7,%zmm25
	vpclmulqdq	$0x10,%zmm27,%zmm4,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x10,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x10,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm10,%zmm31,%zmm26
	vpclmulqdq	$0x10,%zmm30,%zmm7,%zmm25
	vpxord	%zmm25,%zmm24,%zmm24
	vpshufd	$0x4e,%zmm10,%zmm10
	vpclmulqdq	$0x11,%zmm27,%zmm4,%zmm4
	vpclmulqdq	$0x11,%zmm28,%zmm5,%zmm5
	vpclmulqdq	$0x11,%zmm29,%zmm6,%zmm6
	vpternlogd	$0x96,%zmm26,%zmm10,%zmm24
	vpclmulqdq	$0x11,%zmm30,%zmm7,%zmm7
	vpternlogd	$0x96,%zmm6,%zmm5,%zmm4
	vpclmulqdq	$0x01,%zmm24,%zmm31,%zmm25
	vpxord	%zmm7,%zmm4,%zmm10
	vpshufd	$0x4e,%zmm24,%zmm24
	vpternlogd	$0x96,%zmm25,%zmm24,%zmm10
	vextracti32x4	$1,%zmm10,%xmm4
	vextracti32x4	$2,%zmm10,%xmm5
	vextracti32x4	$3,%zmm10,%xmm6
	vpxord	%xmm4,%xmm10,%xmm10
	vpternlogd	$0x96,%xmm5,%xmm6,%xmm10

L$crypt_loop_4x_done__func3:

	testq	%rdx,%rdx
	jz	L$done__func3




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$64,%rdx
	jb	L$partial_vec__func3

L$crypt_loop_1x__func3:



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_full_vec__func3:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_full_vec__func3
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi)


	vmovdqu8	(%r8),%zmm30
	vpshufb	%zmm8,%zmm0,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$64,%r8
	addq	$64,%rdi
	addq	$64,%rsi
	subq	$64,%rdx
	cmpq	$64,%rdx
	jae	L$crypt_loop_1x__func3

	testq	%rdx,%rdx
	jz	L$reduce__func3

L$partial_vec__func3:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k2



	vpshufb	%zmm8,%zmm12,%zmm0
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_partialvec__func3:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_partialvec__func3
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1{%k1}{z}
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi){%k1}













	vmovdqu8	(%r8),%zmm30{%k2}{z}
	vmovdqu8	%zmm0,%zmm1{%k1}{z}
	vpshufb	%zmm8,%zmm1,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6


L$reduce__func3:

	vpclmulqdq	$0x01,%zmm4,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm0,%zmm4,%zmm5
	vpclmulqdq	$0x01,%zmm5,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm5,%zmm5
	vpternlogd	$0x96,%zmm0,%zmm5,%zmm6

	vextracti32x4	$1,%zmm6,%xmm0
	vextracti32x4	$2,%zmm6,%xmm1
	vextracti32x4	$3,%zmm6,%xmm2
	vpxord	%xmm0,%xmm6,%xmm10
	vpternlogd	$0x96,%xmm1,%xmm2,%xmm10


L$done__func3:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



.globl	_aes_gcm_dec_update_vaes_avx10_512
.private_extern _aes_gcm_dec_update_vaes_avx10_512

.p2align	5
_aes_gcm_dec_update_vaes_avx10_512:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12

	vbroadcasti32x4	L$bswap_mask(%rip),%zmm8
	vbroadcasti32x4	L$gfpoly(%rip),%zmm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%zmm12
	vpshufb	%zmm8,%zmm12,%zmm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%zmm13
	vbroadcasti32x4	(%r11),%zmm14


	vpaddd	L$ctr_pattern(%rip),%zmm12,%zmm12


	vbroadcasti32x4	L$inc_4blocks(%rip),%zmm11



	cmpq	$256-1,%rdx
	jbe	L$crypt_loop_4x_done__func4


	vmovdqu8	256-256(%r9),%zmm27
	vmovdqu8	256-192(%r9),%zmm28
	vmovdqu8	256-128(%r9),%zmm29
	vmovdqu8	256-64(%r9),%zmm30
	vbroadcasti32x4	-144(%r11),%zmm15
	vbroadcasti32x4	-128(%r11),%zmm16
	vbroadcasti32x4	-112(%r11),%zmm17
	vbroadcasti32x4	-96(%r11),%zmm18
	vbroadcasti32x4	-80(%r11),%zmm19
	vbroadcasti32x4	-64(%r11),%zmm20
	vbroadcasti32x4	-48(%r11),%zmm21
	vbroadcasti32x4	-32(%r11),%zmm22
	vbroadcasti32x4	-16(%r11),%zmm23
L$crypt_loop_4x__func4:
	vmovdqu8	0(%rdi),%zmm4
	vmovdqu8	64(%rdi),%zmm5
	vmovdqu8	128(%rdi),%zmm6
	vmovdqu8	192(%rdi),%zmm7



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm1
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm2
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm3
	vpaddd	%zmm11,%zmm12,%zmm12


	vpxord	%zmm13,%zmm0,%zmm0
	vpxord	%zmm13,%zmm1,%zmm1
	vpxord	%zmm13,%zmm2,%zmm2
	vpxord	%zmm13,%zmm3,%zmm3

	cmpl	$24,%r10d
	jl	L$aes128__func4
	je	L$aes192__func4

	vbroadcasti32x4	-208(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-192(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes192__func4:
	vbroadcasti32x4	-176(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-160(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes128__func4:
	vpshufb	%zmm8,%zmm4,%zmm4
	vpxord	%zmm10,%zmm4,%zmm4
	vpshufb	%zmm8,%zmm5,%zmm5
	vpshufb	%zmm8,%zmm6,%zmm6

	vaesenc	%zmm15,%zmm0,%zmm0
	vaesenc	%zmm15,%zmm1,%zmm1
	vaesenc	%zmm15,%zmm2,%zmm2
	vaesenc	%zmm15,%zmm3,%zmm3

	vpshufb	%zmm8,%zmm7,%zmm7
	vpclmulqdq	$0x00,%zmm27,%zmm4,%zmm10
	vpclmulqdq	$0x00,%zmm28,%zmm5,%zmm24
	vpclmulqdq	$0x00,%zmm29,%zmm6,%zmm25

	vaesenc	%zmm16,%zmm0,%zmm0
	vaesenc	%zmm16,%zmm1,%zmm1
	vaesenc	%zmm16,%zmm2,%zmm2
	vaesenc	%zmm16,%zmm3,%zmm3

	vpxord	%zmm24,%zmm10,%zmm10
	vpclmulqdq	$0x00,%zmm30,%zmm7,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm10
	vpclmulqdq	$0x01,%zmm27,%zmm4,%zmm24

	vaesenc	%zmm17,%zmm0,%zmm0
	vaesenc	%zmm17,%zmm1,%zmm1
	vaesenc	%zmm17,%zmm2,%zmm2
	vaesenc	%zmm17,%zmm3,%zmm3

	vpclmulqdq	$0x01,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x01,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm30,%zmm7,%zmm25

	vaesenc	%zmm18,%zmm0,%zmm0
	vaesenc	%zmm18,%zmm1,%zmm1
	vaesenc	%zmm18,%zmm2,%zmm2
	vaesenc	%zmm18,%zmm3,%zmm3

	vpclmulqdq	$0x10,%zmm27,%zmm4,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x10,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x10,%zmm29,%zmm6,%zmm26

	vaesenc	%zmm19,%zmm0,%zmm0
	vaesenc	%zmm19,%zmm1,%zmm1
	vaesenc	%zmm19,%zmm2,%zmm2
	vaesenc	%zmm19,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm10,%zmm31,%zmm26
	vpclmulqdq	$0x10,%zmm30,%zmm7,%zmm25
	vpxord	%zmm25,%zmm24,%zmm24

	vaesenc	%zmm20,%zmm0,%zmm0
	vaesenc	%zmm20,%zmm1,%zmm1
	vaesenc	%zmm20,%zmm2,%zmm2
	vaesenc	%zmm20,%zmm3,%zmm3

	vpshufd	$0x4e,%zmm10,%zmm10
	vpclmulqdq	$0x11,%zmm27,%zmm4,%zmm4
	vpclmulqdq	$0x11,%zmm28,%zmm5,%zmm5
	vpclmulqdq	$0x11,%zmm29,%zmm6,%zmm6

	vaesenc	%zmm21,%zmm0,%zmm0
	vaesenc	%zmm21,%zmm1,%zmm1
	vaesenc	%zmm21,%zmm2,%zmm2
	vaesenc	%zmm21,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm10,%zmm24
	vpclmulqdq	$0x11,%zmm30,%zmm7,%zmm7
	vpternlogd	$0x96,%zmm6,%zmm5,%zmm4
	vpclmulqdq	$0x01,%zmm24,%zmm31,%zmm25

	vaesenc	%zmm22,%zmm0,%zmm0
	vaesenc	%zmm22,%zmm1,%zmm1
	vaesenc	%zmm22,%zmm2,%zmm2
	vaesenc	%zmm22,%zmm3,%zmm3

	vpxord	%zmm7,%zmm4,%zmm10
	vpshufd	$0x4e,%zmm24,%zmm24
	vpternlogd	$0x96,%zmm25,%zmm24,%zmm10

	vaesenc	%zmm23,%zmm0,%zmm0
	vaesenc	%zmm23,%zmm1,%zmm1
	vaesenc	%zmm23,%zmm2,%zmm2
	vaesenc	%zmm23,%zmm3,%zmm3

	vextracti32x4	$1,%zmm10,%xmm4
	vextracti32x4	$2,%zmm10,%xmm5
	vextracti32x4	$3,%zmm10,%xmm6
	vpxord	%xmm4,%xmm10,%xmm10
	vpternlogd	$0x96,%xmm5,%xmm6,%xmm10




	vpxord	0(%rdi),%zmm14,%zmm4
	vpxord	64(%rdi),%zmm14,%zmm5
	vpxord	128(%rdi),%zmm14,%zmm6
	vpxord	192(%rdi),%zmm14,%zmm7



	vaesenclast	%zmm4,%zmm0,%zmm4
	vaesenclast	%zmm5,%zmm1,%zmm5
	vaesenclast	%zmm6,%zmm2,%zmm6
	vaesenclast	%zmm7,%zmm3,%zmm7


	vmovdqu8	%zmm4,0(%rsi)
	vmovdqu8	%zmm5,64(%rsi)
	vmovdqu8	%zmm6,128(%rsi)
	vmovdqu8	%zmm7,192(%rsi)

	subq	$-256,%rdi
	subq	$-256,%rsi
	addq	$-256,%rdx
	cmpq	$256-1,%rdx
	ja	L$crypt_loop_4x__func4
L$crypt_loop_4x_done__func4:

	testq	%rdx,%rdx
	jz	L$done__func4




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$64,%rdx
	jb	L$partial_vec__func4

L$crypt_loop_1x__func4:



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_full_vec__func4:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_full_vec__func4
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi)


	vmovdqu8	(%r8),%zmm30
	vpshufb	%zmm8,%zmm1,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$64,%r8
	addq	$64,%rdi
	addq	$64,%rsi
	subq	$64,%rdx
	cmpq	$64,%rdx
	jae	L$crypt_loop_1x__func4

	testq	%rdx,%rdx
	jz	L$reduce__func4

L$partial_vec__func4:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k2



	vpshufb	%zmm8,%zmm12,%zmm0
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_loop_tail_partialvec__func4:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_loop_tail_partialvec__func4
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1{%k1}{z}
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi){%k1}













	vmovdqu8	(%r8),%zmm30{%k2}{z}

	vpshufb	%zmm8,%zmm1,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6


L$reduce__func4:

	vpclmulqdq	$0x01,%zmm4,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm0,%zmm4,%zmm5
	vpclmulqdq	$0x01,%zmm5,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm5,%zmm5
	vpternlogd	$0x96,%zmm0,%zmm5,%zmm6

	vextracti32x4	$1,%zmm6,%xmm0
	vextracti32x4	$2,%zmm6,%xmm1
	vextracti32x4	$3,%zmm6,%xmm2
	vpxord	%xmm0,%xmm6,%xmm10
	vpternlogd	$0x96,%xmm1,%xmm2,%xmm10


L$done__func4:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



#endif
