##############################################################################
#                                                                            #
# Copyright (c) 2015 Intel Corporation                                       #
# Copyright (c) 2015 CloudFlare, Inc.                                        #
# All rights reserved.                                                       #
#                                                                            #
# This software is dual licensed under the Apache V.2.0 and BSD licenses     #
#                                                                            #
##############################################################################
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License");            #
# you may not use this file except in compliance with the License.           #
# You may obtain a copy of the License at                                    #
#                                                                            #
#    http://www.apache.org/licenses/LICENSE-2.0                              #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#                                                                            #
##############################################################################
#                                                                            #
#  Redistribution and use in source and binary forms, with or without        #
#  modification, are permitted provided that the following conditions are    #
#  met:                                                                      #
#                                                                            #
#  #  Redistributions of source code must retain the above copyright         #
#     notice, this list of conditions and the following disclaimer.          #
#                                                                            #
#  #  Redistributions in binary form must reproduce the above copyright      #
#     notice, this list of conditions and the following disclaimer in the    #
#     documentation and/or other materials provided with the                 #
#     distribution.                                                          #
#                                                                            #
#  #  Neither the name of the copyright holders nor the names of its         #
#     contributors may be used to endorse or promote products derived from   #
#     this software without specific prior written permission.               #
#                                                                            #
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       #
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED #
#  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR#
#  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR         #
#  CONTRIBUTORS  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,    #
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,       #
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR        #
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    #
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      #
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        #
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              #
#                                                                            #
##############################################################################
#                                                                            #
#  Developers and authors:                                                   #
#  Shay Gueron (1, 2), and Vlad Krasnov (1, 3)                               #
#  (1) Intel Corporation, Israel Development Center                          #
#  (2) University of Haifa                                                   #
#  (3) CloudFlare, Inc.                                                      #
#  Reference:                                                                #
#  S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with#
#                           256 Bit Primes"                                  #
#                                                                            #
##############################################################################

# NOTE: This only includes the code that is licensed under the above dual
# license. The bulk of the ecp_nistz256-x86_64.pl code is actually in
# p256-x86_64.pl, under the ISC-style license.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

# TODO: enable these after testing. $avx goes to two and $addx to one.
$avx=0;
$addx=0;

$code.=<<___;
.text
.extern	GFp_ia32cap_P

# Constants for computations modulo ord(p256)
.align 64
.Lord:
.quad 0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000
.LordK:
.quad 0xccd1c8aaee00bc4f
___

{
my ($r_ptr,$a_ptr,$b_org,$b_ptr)=("%rdi","%rsi","%rdx","%rbx");
my ($acc0,$acc1,$acc2,$acc3,$acc4,$acc5,$acc6,$acc7)=map("%r$_",(8..15));
my ($t0,$t1,$t2,$t3,$t4)=("%rcx","%rbp","%rbx","%rdx","%rax");
my ($poly1,$poly3)=($acc6,$acc7);

$code.=<<___;
################################################################################
# void GFp_p256_scalar_mul_mont(
#   uint64_t res[4],
#   uint64_t a[4],
#   uint64_t b[4]);

.globl	GFp_p256_scalar_mul_mont
.type	GFp_p256_scalar_mul_mont,\@function,3
.align	32
GFp_p256_scalar_mul_mont:
___
$code.=<<___	if ($addx);
	mov	\$0x80100, %ecx
	and	GFp_ia32cap_P+8(%rip), %ecx
	cmp	\$0x80100, %ecx
	je	ecp_nistz256_ord_mul_montx
___
$code.=<<___;
	push	%rbp
	push	%rbx
	push	%r12
	push	%r13

	mov	$b_org, $b_ptr
	# * b[0]
	mov	8*0($b_ptr), $t0
	mov	8*0($a_ptr), $t4
	mul	$t0
	mov	$t4, $acc0
	mov	$t3, $acc1

	mov	8*1($a_ptr), $t4
	mul	$t0
	add	$t4, $acc1
	adc	\$0, $t3
	mov	$t3, $acc2

	mov	8*2($a_ptr), $t4
	mul	$t0
	add	$t4, $acc2
	adc	\$0, $t3
	mov	$t3, $acc3

	mov	8*3($a_ptr), $t4
	mul	$t0
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $acc4
	xor	$acc5, $acc5

	# First reduction step
	mov	$acc0, $t4
	mulq	.LordK(%rip)
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc0
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc1
	adc	\$0, $t3
	add	$t4, $acc1

	mov	$t0, $t1
	adc	$t3, $acc2
	adc	\$0, $t1
	sub	$t0, $acc2
	sbb	\$0, $t1

	mov	8*3+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc3
	adc	\$0, $t3
	add	$t4, $acc3
	adc	$t3, $acc4
	adc	\$0, $acc5

	# * b[1]
	mov	8*1($b_ptr), $t0

	mov	8*0($a_ptr), $t4
	mul	$t0
	add	$t4, $acc1
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1($a_ptr), $t4
	mul	$t0
	add	$t1, $acc2
	adc	\$0, $t3
	add	$t4, $acc2
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*2($a_ptr), $t4
	mul	$t0
	add	$t1, $acc3
	adc	\$0, $t3
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*3($a_ptr), $t4
	mul	$t0
	add	$t1, $acc4
	adc	\$0, $t3
	add	$t4, $acc4
	adc	$t3, $acc5
	adc	\$0, $acc0
	# Second reduction step
	mov	$acc1, $t4
	mulq	.LordK(%rip)
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc1
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc2
	adc	\$0, $t3
	add	$t4, $acc2

	mov	$t0, $t1
	adc	$t3, $acc3
	adc	\$0, $t1
	sub	$t0, $acc3
	sbb	\$0, $t1

	mov	8*3+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc4
	adc	\$0, $t3
	add	$t4, $acc4
	adc	$t3, $acc5
	adc	\$0, $acc0
	# * b[2]
	mov	8*2($b_ptr), $t0

	mov	8*0($a_ptr), $t4
	mul	$t0
	add	$t4, $acc2
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1($a_ptr), $t4
	mul	$t0
	add	$t1, $acc3
	adc	\$0, $t3
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*2($a_ptr), $t4
	mul	$t0
	add	$t1, $acc4
	adc	\$0, $t3
	add	$t4, $acc4
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*3($a_ptr), $t4
	mul	$t0
	add	$t1, $acc5
	adc	\$0, $t3
	add	$t4, $acc5
	adc	$t3, $acc0
	adc	\$0, $acc1
	# Third reduction step
	mov	$acc2, $t4
	mulq	.LordK(%rip)
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc2
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc3
	adc	\$0, $t3
	add	$t4, $acc3

	mov	$t0, $t1
	adc	$t3, $acc4
	adc	\$0, $t1
	sub	$t0, $acc4
	sbb	\$0, $t1

	mov	8*3+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc5
	adc	\$0, $t3
	add	$t4, $acc5
	adc	$t3, $acc0
	adc	\$0, $acc1
	# * b[3]
	mov	8*3($b_ptr), $t0

	mov	8*0($a_ptr), $t4
	mul	$t0
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1($a_ptr), $t4
	mul	$t0
	add	$t1, $acc4
	adc	\$0, $t3
	add	$t4, $acc4
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*2($a_ptr), $t4
	mul	$t0
	add	$t1, $acc5
	adc	\$0, $t3
	add	$t4, $acc5
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*3($a_ptr), $t4
	mul	$t0
	add	$t1, $acc0
	adc	\$0, $t3
	add	$t4, $acc0
	adc	$t3, $acc1
	adc	\$0, $acc2
	# Last reduction step
	mov	$acc3, $t4
	mulq	.LordK(%rip)
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc4
	adc	\$0, $t3
	add	$t4, $acc4

	mov	$t0, $t1
	adc	$t3, $acc5
	adc	\$0, $t1
	sub	$t0, $acc5
	sbb	\$0, $t1

	mov	8*3+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc0
	adc	\$0, $t3
	add	$t4, $acc0
	adc	$t3, $acc1
	adc	\$0, $acc2

	# Copy result [255:0]
	mov	$acc4, $a_ptr
	mov	$acc5, $acc3
	mov	$acc0, $t0
	mov	$acc1, $t1
	# Subtract ord
	sub	8*0+.Lord(%rip), $acc4
	sbb	8*1+.Lord(%rip), $acc5
	sbb	8*2+.Lord(%rip), $acc0
	sbb	8*3+.Lord(%rip), $acc1
	sbb	\$0, $acc2

	cmovc	$a_ptr, $acc4
	cmovc	$acc3, $acc5
	cmovc	$t0, $acc0
	cmovc	$t1, $acc1

	mov	$acc4, 8*0($r_ptr)
	mov	$acc5, 8*1($r_ptr)
	mov	$acc0, 8*2($r_ptr)
	mov	$acc1, 8*3($r_ptr)

	pop	%r13
	pop	%r12
	pop	%rbx
	pop	%rbp
	ret
.size	GFp_p256_scalar_mul_mont,.-GFp_p256_scalar_mul_mont
___
$code.=<<___	if ($addx);
################################################################################
.align	32
ecp_nistz256_ord_mul_montx:
	push	%rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	$b_org, $b_ptr
	mov	8*0($b_org), %rdx
	mov	8*0($a_ptr), $acc1
	mov	8*1($a_ptr), $acc2
	mov	8*2($a_ptr), $acc3
	mov	8*3($a_ptr), $acc4
	lea	-128($a_ptr), $a_ptr	# control u-op density

	# Multiply by b[0]
	mulx	$acc1, $acc0, $acc1
	mulx	$acc2, $t0, $acc2
	xor	$acc5, $acc5		# cf=0
	mulx	$acc3, $t1, $acc3
	adc	$t0, $acc1
	mulx	$acc4, $t0, $acc4
	 mov	$acc0, %rdx
	mulx	.LordK(%rip), %rdx, $t4
	adc	$t1, $acc2
	adc	$t0, $acc3
	adc	\$0, $acc4

	########################################################################
	xor %eax, %eax
	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc0
	adox	$t1, $acc1
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc1
	adox	$t1, $acc2
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc4
	mov	8*1($b_ptr), %rdx
	adcx	%rax, $acc4
	adox	%rax, $acc5
	adc	\$0, $acc5
	xor	$acc0 ,$acc0
	########################################################################
	# Multiply by b[1]
	mulx	8*0+128($a_ptr), $t0, $t1
	adcx	$t0, $acc1
	adox	$t1, $acc2

	mulx	8*1+128($a_ptr), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3

	mulx	8*2+128($a_ptr), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc4

	mulx	8*3+128($a_ptr), $t0, $t1
	 mov	$acc1, %rdx
	mulx	.LordK(%rip), %rdx, $t4
	adcx	$t0, $acc4
	adox	$t1, $acc5

	adcx	$acc0, $acc5
	adox	$acc0, $acc0
	adc	\$0, $acc0
	########################################################################
	xor	%eax, %eax
	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc1
	adox	$t1, $acc2
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc4
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc4
	adox	$t1, $acc5
	mov	8*2($b_ptr), %rdx
	adcx	%rax, $acc5
	adox	%rax, $acc0
	adc	\$0, $acc0
	xor	$acc1 ,$acc1		# $acc1=0,cf=0,of=0
	########################################################################
	# Multiply by b[2]
	mulx	8*0+128($a_ptr), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3

	mulx	8*1+128($a_ptr), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc4

	mulx	8*2+128($a_ptr), $t0, $t1
	adcx	$t0, $acc4
	adox	$t1, $acc5

	mulx	8*3+128($a_ptr), $t0, $t1
	 mov	$acc2, %rdx
	mulx	.LordK(%rip), %rdx, $t4
	adcx	$t0, $acc5
	adox	$t1, $acc0

	adcx	$acc1, $acc0
	adox	$acc1, $acc1
	adc	\$0, $acc1

	########################################################################
	xor	%eax, %eax
	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc4
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc4
	adox	$t1, $acc5
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc5
	adox	$t1, $acc0
	mov	8*3($b_ptr), %rdx
	adcx	%rax, $acc0
	adox	%rax, $acc1
	adc	\$0, $acc1
	xor	$acc2 ,$acc2		# $acc2=0,cf=0,of=0
	########################################################################
	# Multiply by b[3]
	mulx	8*0+128($a_ptr), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc4

	mulx	8*1+128($a_ptr), $t0, $t1
	adcx	$t0, $acc4
	adox	$t1, $acc5

	mulx	8*2+128($a_ptr), $t0, $t1
	adcx	$t0, $acc5
	adox	$t1, $acc0

	mulx	8*3+128($a_ptr), $t0, $t1
	 mov	$acc3, %rdx
	mulx	.LordK(%rip), %rdx, $t4
	adcx	$t0, $acc0
	adox	$t1, $acc1

	adcx	$acc2, $acc1
	adox	$acc2, $acc2
	adc	\$0, $acc2

	########################################################################
	xor	%eax, %eax
	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc4
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc4
	adox	$t1, $acc5
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc5
	adox	$t1, $acc0
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc0
	adox	$t1, $acc1
	adcx	%rax, $acc1
	adox	%rax, $acc2
	adc	\$0, $acc2

	########################################################################
	# Branch-less conditional subtraction of P
	xor	%eax, %eax
	 mov	$acc4, $t2
	 mov	$acc5, $t3
	 mov	$acc0, $t0
	 mov	$acc1, $t1
	sbb	8*0+.Lord(%rip), $acc4		# .Lpoly[0]
	sbb	8*1+.Lord(%rip), $acc5		# .Lpoly[1]
	sbb	8*2+.Lord(%rip), $acc0		# .Lpoly[1]
	sbb	8*3+.Lord(%rip), $acc1		# .Lpoly[1]
	sbb	\$0, $acc2

	cmovc	$t2, $acc4
	cmovc	$t3, $acc5
	mov	$acc4, 8*0($r_ptr)
	cmovc	$t0, $acc0
	mov	$acc5, 8*1($r_ptr)
	cmovc	$t1, $acc1
	mov	$acc0, 8*2($r_ptr)
	mov	$acc1, 8*3($r_ptr)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	pop	%rbp
	ret
.size	ecp_nistz256_ord_mul_montx,.-ecp_nistz256_ord_mul_montx
################################################################################
___
$code.=<<___;
# void GFp_p256_scalar_sqr_rep_mont(
#   uint64_t res[4],
#   uint64_t a[4],
#   int rep);

.globl	GFp_p256_scalar_sqr_rep_mont
.type	GFp_p256_scalar_sqr_rep_mont,\@function,3
.align	32
GFp_p256_scalar_sqr_rep_mont:

___
$code.=<<___	if ($addx);
	mov	\$0x80100, %ecx
	and	GFp_ia32cap_P+8(%rip), %ecx
	cmp	\$0x80100, %ecx
	je	ecp_nistz256_ord_sqr_montx
___
$code.=<<___;
	push	%rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	.LordK(%rip), %r15

	mov	$b_org, %r14

.Lord_sqr_loop:
	# y[1:] * y[0]
	mov	8*0($a_ptr), $t0

	mov	8*1($a_ptr), $t4
	mul	$t0
	mov	$t4, $acc1
	mov	$t3, $acc2

	mov	8*2($a_ptr), $t4
	mul	$t0
	add	$t4, $acc2
	adc	\$0, $t3
	mov	$t3, $acc3

	mov	8*3($a_ptr), $t4
	mul	$t0
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $acc4
	# y[2:] * y[1]
	mov	8*1($a_ptr), $t0

	mov	8*2($a_ptr), $t4
	mul	$t0
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*3($a_ptr), $t4
	mul	$t0
	add	$t1, $acc4
	adc	\$0, $t3
	add	$t4, $acc4
	adc	\$0, $t3
	mov	$t3, $acc5
	# y[3] * y[2]
	mov	8*2($a_ptr), $t0

	mov	8*3($a_ptr), $t4
	mul	$t0
	add	$t4, $acc5
	adc	\$0, $t3
	mov	$t3, $b_ptr
	xor	$t1, $t1
	# *2
	add	$acc1, $acc1
	adc	$acc2, $acc2
	adc	$acc3, $acc3
	adc	$acc4, $acc4
	adc	$acc5, $acc5
	adc	$b_ptr, $b_ptr
	adc	\$0, $t1
	# Missing products
	mov	8*0($a_ptr), $t4
	mul	$t4
	mov	$t4, $acc0
	mov	$t3, $t0

	mov	8*1($a_ptr), $t4
	mul	$t4
	add	$t0, $acc1
	adc	$t4, $acc2
	adc	\$0, $t3
	mov	$t3, $t0

	mov	8*2($a_ptr), $t4
	mul	$t4
	add	$t0, $acc3
	adc	$t4, $acc4
	adc	\$0, $t3
	mov	$t3, $t0

	mov	8*3($a_ptr), $t4
	mul	$t4
	add	$t0, $acc5
	adc	$t4, $b_ptr
	adc	$t3, $t1
	mov	$t1, $a_ptr

	# First reduction step
	mov	$acc0, $t4
	mulq	%r15
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc0
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc1
	adc	\$0, $t3
	add	$t4, $acc1

	mov	$t0, $t1
	adc	$t3, $acc2
	adc	\$0, $t1
	sub	$t0, $acc2
	sbb	\$0, $t1

	mov	$t0, $t4
	mov	$t0, $t3
	mov	$t0, $acc0
	shl	\$32, $t4
	shr	\$32, $t3

	add	$t1, $acc3
	adc	\$0, $acc0
	sub	$t4, $acc3
	sbb	$t3, $acc0

	# Second reduction step
	mov	$acc1, $t4
	mulq	%r15
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc1
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc2
	adc	\$0, $t3
	add	$t4, $acc2

	mov	$t0, $t1
	adc	$t3, $acc3
	adc	\$0, $t1
	sub	$t0, $acc3
	sbb	\$0, $t1

	mov	$t0, $t4
	mov	$t0, $t3
	mov	$t0, $acc1
	shl	\$32, $t4
	shr	\$32, $t3

	add	$t1, $acc0
	adc	\$0, $acc1
	sub	$t4, $acc0
	sbb	$t3, $acc1

	# Third reduction step
	mov	$acc2, $t4
	mulq	%r15
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc2
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc3
	adc	\$0, $t3
	add	$t4, $acc3

	mov	$t0, $t1
	adc	$t3, $acc0
	adc	\$0, $t1
	sub	$t0, $acc0
	sbb	\$0, $t1

	mov	$t0, $t4
	mov	$t0, $t3
	mov	$t0, $acc2
	shl	\$32, $t4
	shr	\$32, $t3

	add	$t1, $acc1
	adc	\$0, $acc2
	sub	$t4, $acc1
	sbb	$t3, $acc2

	# Last reduction step
	mov	$acc3, $t4
	mulq	%r15
	mov	$t4, $t0

	mov	8*0+.Lord(%rip), $t4
	mul	$t0
	add	$t4, $acc3
	adc	\$0, $t3
	mov	$t3, $t1

	mov	8*1+.Lord(%rip), $t4
	mul	$t0
	add	$t1, $acc0
	adc	\$0, $t3
	add	$t4, $acc0

	mov	$t0, $t1
	adc	$t3, $acc1
	adc	\$0, $t1
	sub	$t0, $acc1
	sbb	\$0, $t1

	mov	$t0, $t4
	mov	$t0, $acc3
	shl	\$32, $t4
	shr	\$32, $t0

	add	$t1, $acc2
	adc	\$0, $acc3
	sub	$t4, $acc2
	sbb	$t0, $acc3
	xor	$t0, $t0
	# Add bits [511:256] of	the sqr result
	add	$acc4, $acc0
	adc	$acc5, $acc1
	adc	$b_ptr, $acc2
	adc	$a_ptr, $acc3
	adc	\$0, $t0

	mov	$acc0, $acc4
	mov	$acc1, $acc5
	mov	$acc2, $b_ptr
	mov	$acc3, $t1
	# Subtract p256
	sub	8*0+.Lord(%rip), $acc0
	sbb	8*1+.Lord(%rip), $acc1
	sbb	8*2+.Lord(%rip), $acc2
	sbb	8*3+.Lord(%rip), $acc3
	sbb	\$0, $t0

	cmovc	$acc4, $acc0
	cmovc	$acc5, $acc1
	cmovc	$b_ptr, $acc2
	cmovc	$t1, $acc3

	mov	$acc0, 8*0($r_ptr)
	mov	$acc1, 8*1($r_ptr)
	mov	$acc2, 8*2($r_ptr)
	mov	$acc3, 8*3($r_ptr)
	mov	$r_ptr, $a_ptr
	dec	%r14
	jne	.Lord_sqr_loop

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	pop	%rbp
	ret
.size	GFp_p256_scalar_sqr_rep_mont,.-GFp_p256_scalar_sqr_rep_mont
___
$code.=<<___	if ($addx);
.align	32
ecp_nistz256_ord_sqr_montx:

	push	%rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	$b_org, $t2
	lea	-128($a_ptr), $a_ptr	# control u-op density

.Lord_sqrx_loop:
	mov	8*0+128($a_ptr), %rdx
	mov	8*1+128($a_ptr), $acc6
	mov	8*2+128($a_ptr), $acc7
	mov	8*3+128($a_ptr), $acc0

	mulx	$acc6, $acc1, $acc2	# a[0]*a[1]
	mulx	$acc7, $t0, $acc3	# a[0]*a[2]
	xor	%eax, %eax
	adc	$t0, $acc2
	mulx	$acc0, $t1, $acc4	# a[0]*a[3]
	 mov	$acc6, %rdx
	adc	$t1, $acc3
	adc	\$0, $acc4
	xor	$acc5, $acc5		# $acc5=0,cf=0,of=0
	#################################
	mulx	$acc7, $t0, $t1		# a[1]*a[2]
	adcx	$t0, $acc3
	adox	$t1, $acc4

	mulx	$acc0, $t0, $t1		# a[1]*a[3]
	 mov	$acc7, %rdx
	adcx	$t0, $acc4
	adox	$t1, $acc5
	adc	\$0, $acc5
	#################################
	mulx	$acc0, $t0, $acc6	# a[2]*a[3]
	 mov	8*0+128($a_ptr), %rdx
	xor	$acc7, $acc7		# $acc7=0,cf=0,of=0
	 adcx	$acc1, $acc1		# acc1:6<<1
	adox	$t0, $acc5
	 adcx	$acc2, $acc2
	adox	$acc7, $acc6		# of=0

	mulx	%rdx, $acc0, $t1
	mov	8*1+128($a_ptr), %rdx
	 adcx	$acc3, $acc3
	adox	$t1, $acc1
	 adcx	$acc4, $acc4
	mulx	%rdx, $t0, $t4
	mov	8*2+128($a_ptr), %rdx
	 adcx	$acc5, $acc5
	adox	$t0, $acc2
	 adcx	$acc6, $acc6
	.byte	0x67
	mulx	%rdx, $t0, $t1
	mov	8*3+128($a_ptr), %rdx
	adox	$t4, $acc3
	 adcx	$acc7, $acc7
	adox	$t0, $acc4
	adox	$t1, $acc5
	.byte	0x67,0x67
	mulx	%rdx, $t0, $t4
	adox	$t0, $acc6
	adox	$t4, $acc7

	#reduce
	mov	$acc0, %rdx
	mulx	.LordK(%rip), %rdx, $t0

	xor	%eax, %eax
	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc0
	adox	$t1, $acc1
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc1
	adox	$t1, $acc2
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc0
	adcx	%rax, $acc0
	#################################
	mov	$acc1, %rdx
	mulx	.LordK(%rip), %rdx, $t0

	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc1
	adox	$t1, $acc2
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc0
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc0
	adox	$t1, $acc1
	adcx	%rax, $acc1
	#################################
	mov	$acc2, %rdx
	mulx	.LordK(%rip), %rdx, $t0

	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc0
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc0
	adox	$t1, $acc1
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc1
	adox	$t1, $acc2
	adcx	%rax, $acc2
	#################################
	mov	$acc3, %rdx
	mulx	.LordK(%rip), %rdx, $t0

	mulx	8*0+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc3
	adox	$t1, $acc0
	mulx	8*1+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc0
	adox	$t1, $acc1
	mulx	8*2+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc1
	adox	$t1, $acc2
	mulx	8*3+.Lord(%rip), $t0, $t1
	adcx	$t0, $acc2
	adox	$t1, $acc3
	adcx	%rax, $acc3

	xor	$t0, $t0
	add	$acc4, $acc0
	adc	$acc5, $acc1
	adc	$acc6, $acc2
	adc	$acc7, $acc3
	adc	\$0, $t0

	mov	$acc0, $acc4
	mov	$acc1, $acc5
	mov	$acc2, $acc6
	mov	$acc3, $acc7
	# Subtract p256
	sub	8*0+.Lord(%rip), $acc0
	sbb	8*1+.Lord(%rip), $acc1
	sbb	8*2+.Lord(%rip), $acc2
	sbb	8*3+.Lord(%rip), $acc3
	sbb	\$0, $t0

	cmovc	$acc4, $acc0
	cmovc	$acc5, $acc1
	cmovc	$acc6, $acc2
	cmovc	$acc7, $acc3

	mov	$acc0, 8*0($r_ptr)
	mov	$acc1, 8*1($r_ptr)
	mov	$acc2, 8*2($r_ptr)
	mov	$acc3, 8*3($r_ptr)

	lea	-128($r_ptr), $a_ptr

	dec	$t2
	jne	.Lord_sqrx_loop

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	pop	%rbp
	ret

.size	ecp_nistz256_ord_sqr_montx,.-ecp_nistz256_ord_sqr_montx
___
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;
