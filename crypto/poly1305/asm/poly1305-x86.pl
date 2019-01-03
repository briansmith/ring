#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# This module implements Poly1305 hash for x86.
#
# April 2015
#
# Numbers are cycles per processed byte with poly1305_blocks alone,
# measured with rdtsc at fixed clock frequency.
#
#		IALU/gcc-3.4(*)	SSE2(**)	AVX2
# Pentium	15.7/+80%	-
# PIII		6.21/+90%	-
# P4		19.8/+40%	3.24
# Core 2	4.85/+90%	1.80
# Westmere	4.58/+100%	1.43
# Sandy Bridge	3.90/+100%	1.36
# Haswell	3.88/+70%	1.18		0.72
# Silvermont	11.0/+40%	4.80
# VIA Nano	6.71/+90%	2.47
# Sledgehammer	3.51/+180%	4.27
# Bulldozer	4.53/+140%	1.31
#
# (*)	gcc 4.8 for some reason generated worse code;
# (**)	besides SSE2 there are floating-point and AVX options; FP
#	is deemed unnecessary, because pre-SSE2 processor are too
#	old to care about, while it's not the fastest option on
#	SSE2-capable ones; AVX is omitted, because it doesn't give
#	a lot of improvement, 5-10% depending on processor;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";

$output=pop;
open STDOUT,">$output";

&asm_init($ARGV[0],"poly1305-x86.pl",$ARGV[$#ARGV] eq "386");

$sse2=$avx=0;
for (@ARGV) { $sse2=1 if (/-DOPENSSL_IA32_SSE2/); }

if ($sse2) {
	&static_label("const_sse2");
	&static_label("enter_blocks");
	&static_label("enter_emit");
	&external_label("RingCore_ia32cap_P");

	# This may be set to 2, but valgrind can't do AVX2 on 32-bit. Without a
	# way to verify test coverage, keep it disabled.
	# The AVX2 code was removed.
	$avx = 0;
}

########################################################################
# Layout of opaque area is following.
#
#	unsigned __int32 h[5];		# current hash value base 2^32
#	unsigned __int32 pad;		# is_base2_26 in vector context
#	unsigned __int32 r[4];		# key value base 2^32

&align(64);
&function_begin("RingCore_poly1305_init_asm");
	&mov	("edi",&wparam(0));		# context
	&mov	("esi",&wparam(1));		# key
	&mov	("ebp",&wparam(2));		# function table

	&xor	("eax","eax");
	&mov	(&DWP(4*0,"edi"),"eax");	# zero hash value
	&mov	(&DWP(4*1,"edi"),"eax");
	&mov	(&DWP(4*2,"edi"),"eax");
	&mov	(&DWP(4*3,"edi"),"eax");
	&mov	(&DWP(4*4,"edi"),"eax");
	&mov	(&DWP(4*5,"edi"),"eax");	# is_base2_26

	&cmp	("esi",0);
	&je	(&label("nokey"));

    if ($sse2) {
	&call	(&label("pic_point"));
    &set_label("pic_point");
	&blindpop("ebx");

	&lea	("eax",&DWP("RingCore_poly1305_blocks-".&label("pic_point"),"ebx"));
	&lea	("edx",&DWP("RingCore_poly1305_emit-".&label("pic_point"),"ebx"));

	&picmeup("edi","RingCore_ia32cap_P","ebx",&label("pic_point"));
	&mov	("ecx",&DWP(0,"edi"));
	&and	("ecx",1<<26|1<<24);
	&cmp	("ecx",1<<26|1<<24);		# SSE2 and XMM?
	# The non-SSE2 code was removed. 

	&lea	("eax",&DWP("_poly1305_blocks_sse2-".&label("pic_point"),"ebx"));
	&lea	("edx",&DWP("_poly1305_emit_sse2-".&label("pic_point"),"ebx"));

	# AVX2 code removed.

    # The non-SSE2 code was removed.

	&mov	("edi",&wparam(0));		# reload context
	&mov	(&DWP(0,"ebp"),"eax");		# fill function table
	&mov	(&DWP(4,"ebp"),"edx");
    }

	&mov	("eax",&DWP(4*0,"esi"));	# load input key
	&mov	("ebx",&DWP(4*1,"esi"));
	&mov	("ecx",&DWP(4*2,"esi"));
	&mov	("edx",&DWP(4*3,"esi"));
	&and	("eax",0x0fffffff);
	&and	("ebx",0x0ffffffc);
	&and	("ecx",0x0ffffffc);
	&and	("edx",0x0ffffffc);
	&mov	(&DWP(4*6,"edi"),"eax");
	&mov	(&DWP(4*7,"edi"),"ebx");
	&mov	(&DWP(4*8,"edi"),"ecx");
	&mov	(&DWP(4*9,"edi"),"edx");

	&mov	("eax",$sse2);
&set_label("nokey");
&function_end("RingCore_poly1305_init_asm");

($h0,$h1,$h2,$h3,$h4,
 $d0,$d1,$d2,$d3,
 $r0,$r1,$r2,$r3,
     $s1,$s2,$s3)=map(4*$_,(0..15));

&function_begin("RingCore_poly1305_blocks");
	&mov	("edi",&wparam(0));		# ctx
	&mov	("esi",&wparam(1));		# inp
	&mov	("ecx",&wparam(2));		# len
&set_label("enter_blocks");
	&and	("ecx",-15);
	&jz	(&label("nodata"));

	&stack_push(16);
	&mov	("eax",&DWP(4*6,"edi"));	# r0
	&mov	("ebx",&DWP(4*7,"edi"));	# r1
	 &lea	("ebp",&DWP(0,"esi","ecx"));	# end of input
	&mov	("ecx",&DWP(4*8,"edi"));	# r2
	&mov	("edx",&DWP(4*9,"edi"));	# r3

	&mov	(&wparam(2),"ebp");
	&mov	("ebp","esi");

	&mov	(&DWP($r0,"esp"),"eax");	# r0
	&mov	("eax","ebx");
	&shr	("eax",2);
	&mov	(&DWP($r1,"esp"),"ebx");	# r1
	&add	("eax","ebx");			# s1
	&mov	("ebx","ecx");
	&shr	("ebx",2);
	&mov	(&DWP($r2,"esp"),"ecx");	# r2
	&add	("ebx","ecx");			# s2
	&mov	("ecx","edx");
	&shr	("ecx",2);
	&mov	(&DWP($r3,"esp"),"edx");	# r3
	&add	("ecx","edx");			# s3
	&mov	(&DWP($s1,"esp"),"eax");	# s1
	&mov	(&DWP($s2,"esp"),"ebx");	# s2
	&mov	(&DWP($s3,"esp"),"ecx");	# s3

	&mov	("eax",&DWP(4*0,"edi"));	# load hash value
	&mov	("ebx",&DWP(4*1,"edi"));
	&mov	("ecx",&DWP(4*2,"edi"));
	&mov	("esi",&DWP(4*3,"edi"));
	&mov	("edi",&DWP(4*4,"edi"));
	&jmp	(&label("loop"));

&set_label("loop",32);
	&add	("eax",&DWP(4*0,"ebp"));	# accumulate input
	&adc	("ebx",&DWP(4*1,"ebp"));
	&adc	("ecx",&DWP(4*2,"ebp"));
	&adc	("esi",&DWP(4*3,"ebp"));
	&lea	("ebp",&DWP(4*4,"ebp"));
	&adc	("edi",&wparam(3));		# padbit

	&mov	(&DWP($h0,"esp"),"eax");	# put aside hash[+inp]
	&mov	(&DWP($h3,"esp"),"esi");

	&mul	(&DWP($r0,"esp"));		# h0*r0
	 &mov	(&DWP($h4,"esp"),"edi");
	&mov	("edi","eax");
	&mov	("eax","ebx");			# h1
	&mov	("esi","edx");
	&mul	(&DWP($s3,"esp"));		# h1*s3
	&add	("edi","eax");
	&mov	("eax","ecx");			# h2
	&adc	("esi","edx");
	&mul	(&DWP($s2,"esp"));		# h2*s2
	&add	("edi","eax");
	&mov	("eax",&DWP($h3,"esp"));
	&adc	("esi","edx");
	&mul	(&DWP($s1,"esp"));		# h3*s1
	&add	("edi","eax");
	 &mov	("eax",&DWP($h0,"esp"));
	&adc	("esi","edx");

	&mul	(&DWP($r1,"esp"));		# h0*r1
	 &mov	(&DWP($d0,"esp"),"edi");
	&xor	("edi","edi");
	&add	("esi","eax");
	&mov	("eax","ebx");			# h1
	&adc	("edi","edx");
	&mul	(&DWP($r0,"esp"));		# h1*r0
	&add	("esi","eax");
	&mov	("eax","ecx");			# h2
	&adc	("edi","edx");
	&mul	(&DWP($s3,"esp"));		# h2*s3
	&add	("esi","eax");
	&mov	("eax",&DWP($h3,"esp"));
	&adc	("edi","edx");
	&mul	(&DWP($s2,"esp"));		# h3*s2
	&add	("esi","eax");
	&mov	("eax",&DWP($h4,"esp"));
	&adc	("edi","edx");
	&imul	("eax",&DWP($s1,"esp"));	# h4*s1
	&add	("esi","eax");
	 &mov	("eax",&DWP($h0,"esp"));
	&adc	("edi",0);

	&mul	(&DWP($r2,"esp"));		# h0*r2
	 &mov	(&DWP($d1,"esp"),"esi");
	&xor	("esi","esi");
	&add	("edi","eax");
	&mov	("eax","ebx");			# h1
	&adc	("esi","edx");
	&mul	(&DWP($r1,"esp"));		# h1*r1
	&add	("edi","eax");
	&mov	("eax","ecx");			# h2
	&adc	("esi","edx");
	&mul	(&DWP($r0,"esp"));		# h2*r0
	&add	("edi","eax");
	&mov	("eax",&DWP($h3,"esp"));
	&adc	("esi","edx");
	&mul	(&DWP($s3,"esp"));		# h3*s3
	&add	("edi","eax");
	&mov	("eax",&DWP($h4,"esp"));
	&adc	("esi","edx");
	&imul	("eax",&DWP($s2,"esp"));	# h4*s2
	&add	("edi","eax");
	 &mov	("eax",&DWP($h0,"esp"));
	&adc	("esi",0);

	&mul	(&DWP($r3,"esp"));		# h0*r3
	 &mov	(&DWP($d2,"esp"),"edi");
	&xor	("edi","edi");
	&add	("esi","eax");
	&mov	("eax","ebx");			# h1
	&adc	("edi","edx");
	&mul	(&DWP($r2,"esp"));		# h1*r2
	&add	("esi","eax");
	&mov	("eax","ecx");			# h2
	&adc	("edi","edx");
	&mul	(&DWP($r1,"esp"));		# h2*r1
	&add	("esi","eax");
	&mov	("eax",&DWP($h3,"esp"));
	&adc	("edi","edx");
	&mul	(&DWP($r0,"esp"));		# h3*r0
	&add	("esi","eax");
	 &mov	("ecx",&DWP($h4,"esp"));
	&adc	("edi","edx");

	&mov	("edx","ecx");
	&imul	("ecx",&DWP($s3,"esp"));	# h4*s3
	&add	("esi","ecx");
	 &mov	("eax",&DWP($d0,"esp"));
	&adc	("edi",0);

	&imul	("edx",&DWP($r0,"esp"));	# h4*r0
	&add	("edx","edi");

	&mov	("ebx",&DWP($d1,"esp"));
	&mov	("ecx",&DWP($d2,"esp"));

	&mov	("edi","edx");			# last reduction step
	&shr	("edx",2);
	&and	("edi",3);
	&lea	("edx",&DWP(0,"edx","edx",4));	# *5
	&add	("eax","edx");
	&adc	("ebx",0);
	&adc	("ecx",0);
	&adc	("esi",0);
	&adc	("edi",0);

	&cmp	("ebp",&wparam(2));		# done yet?
	&jne	(&label("loop"));

	&mov	("edx",&wparam(0));		# ctx
	&stack_pop(16);
	&mov	(&DWP(4*0,"edx"),"eax");	# store hash value
	&mov	(&DWP(4*1,"edx"),"ebx");
	&mov	(&DWP(4*2,"edx"),"ecx");
	&mov	(&DWP(4*3,"edx"),"esi");
	&mov	(&DWP(4*4,"edx"),"edi");
&set_label("nodata");
&function_end("RingCore_poly1305_blocks");

&function_begin("RingCore_poly1305_emit");
	&mov	("ebp",&wparam(0));		# context
&set_label("enter_emit");
	&mov	("edi",&wparam(1));		# output
	&mov	("eax",&DWP(4*0,"ebp"));	# load hash value
	&mov	("ebx",&DWP(4*1,"ebp"));
	&mov	("ecx",&DWP(4*2,"ebp"));
	&mov	("edx",&DWP(4*3,"ebp"));
	&mov	("esi",&DWP(4*4,"ebp"));

	&add	("eax",5);			# compare to modulus
	&adc	("ebx",0);
	&adc	("ecx",0);
	&adc	("edx",0);
	&adc	("esi",0);
	&shr	("esi",2);			# did it carry/borrow?
	&neg	("esi");			# do we choose hash-modulus?

	&and	("eax","esi");
	&and	("ebx","esi");
	&and	("ecx","esi");
	&and	("edx","esi");
	&mov	(&DWP(4*0,"edi"),"eax");
	&mov	(&DWP(4*1,"edi"),"ebx");
	&mov	(&DWP(4*2,"edi"),"ecx");
	&mov	(&DWP(4*3,"edi"),"edx");

	&not	("esi");			# or original hash value?
	&mov	("eax",&DWP(4*0,"ebp"));
	&mov	("ebx",&DWP(4*1,"ebp"));
	&mov	("ecx",&DWP(4*2,"ebp"));
	&mov	("edx",&DWP(4*3,"ebp"));
	&mov	("ebp",&wparam(2));
	&and	("eax","esi");
	&and	("ebx","esi");
	&and	("ecx","esi");
	&and	("edx","esi");
	&or	("eax",&DWP(4*0,"edi"));
	&or	("ebx",&DWP(4*1,"edi"));
	&or	("ecx",&DWP(4*2,"edi"));
	&or	("edx",&DWP(4*3,"edi"));

	&add	("eax",&DWP(4*0,"ebp"));	# accumulate key
	&adc	("ebx",&DWP(4*1,"ebp"));
	&adc	("ecx",&DWP(4*2,"ebp"));
	&adc	("edx",&DWP(4*3,"ebp"));

	&mov	(&DWP(4*0,"edi"),"eax");
	&mov	(&DWP(4*1,"edi"),"ebx");
	&mov	(&DWP(4*2,"edi"),"ecx");
	&mov	(&DWP(4*3,"edi"),"edx");
&function_end("RingCore_poly1305_emit");

if ($sse2) {
########################################################################
# Layout of opaque area is following.
#
#	unsigned __int32 h[5];		# current hash value base 2^26
#	unsigned __int32 is_base2_26;
#	unsigned __int32 r[4];		# key value base 2^32
#	unsigned __int32 pad[2];
#	struct { unsigned __int32 r^4, r^3, r^2, r^1; } r[9];
#
# where r^n are base 2^26 digits of degrees of multiplier key. There are
# 5 digits, but last four are interleaved with multiples of 5, totalling
# in 9 elements: r0, r1, 5*r1, r2, 5*r2, r3, 5*r3, r4, 5*r4.

my ($D0,$D1,$D2,$D3,$D4,$T0,$T1,$T2)=map("xmm$_",(0..7));
my $MASK=$T2;	# borrow and keep in mind

&align	(32);
&function_begin_B("_poly1305_init_sse2");
	&movdqu		($D4,&QWP(4*6,"edi"));		# key base 2^32
	&lea		("edi",&DWP(16*3,"edi"));	# size optimization
	&mov		("ebp","esp");
	&sub		("esp",16*(9+5));
	&and		("esp",-16);

	#&pand		($D4,&QWP(96,"ebx"));		# magic mask
	&movq		($MASK,&QWP(64,"ebx"));

	&movdqa		($D0,$D4);
	&movdqa		($D1,$D4);
	&movdqa		($D2,$D4);

	&pand		($D0,$MASK);			# -> base 2^26
	&psrlq		($D1,26);
	&psrldq		($D2,6);
	&pand		($D1,$MASK);
	&movdqa		($D3,$D2);
	&psrlq		($D2,4)
	&psrlq		($D3,30);
	&pand		($D2,$MASK);
	&pand		($D3,$MASK);
	&psrldq		($D4,13);

	&lea		("edx",&DWP(16*9,"esp"));	# size optimization
	&mov		("ecx",2);
&set_label("square");
	&movdqa		(&QWP(16*0,"esp"),$D0);
	&movdqa		(&QWP(16*1,"esp"),$D1);
	&movdqa		(&QWP(16*2,"esp"),$D2);
	&movdqa		(&QWP(16*3,"esp"),$D3);
	&movdqa		(&QWP(16*4,"esp"),$D4);

	&movdqa		($T1,$D1);
	&movdqa		($T0,$D2);
	&pslld		($T1,2);
	&pslld		($T0,2);
	&paddd		($T1,$D1);			# *5
	&paddd		($T0,$D2);			# *5
	&movdqa		(&QWP(16*5,"esp"),$T1);
	&movdqa		(&QWP(16*6,"esp"),$T0);
	&movdqa		($T1,$D3);
	&movdqa		($T0,$D4);
	&pslld		($T1,2);
	&pslld		($T0,2);
	&paddd		($T1,$D3);			# *5
	&paddd		($T0,$D4);			# *5
	&movdqa		(&QWP(16*7,"esp"),$T1);
	&movdqa		(&QWP(16*8,"esp"),$T0);

	&pshufd		($T1,$D0,0b01000100);
	&movdqa		($T0,$D1);
	&pshufd		($D1,$D1,0b01000100);
	&pshufd		($D2,$D2,0b01000100);
	&pshufd		($D3,$D3,0b01000100);
	&pshufd		($D4,$D4,0b01000100);
	&movdqa		(&QWP(16*0,"edx"),$T1);
	&movdqa		(&QWP(16*1,"edx"),$D1);
	&movdqa		(&QWP(16*2,"edx"),$D2);
	&movdqa		(&QWP(16*3,"edx"),$D3);
	&movdqa		(&QWP(16*4,"edx"),$D4);

	################################################################
	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4

	&pmuludq	($D4,$D0);			# h4*r0
	&pmuludq	($D3,$D0);			# h3*r0
	&pmuludq	($D2,$D0);			# h2*r0
	&pmuludq	($D1,$D0);			# h1*r0
	&pmuludq	($D0,$T1);			# h0*r0

sub pmuladd {
my $load = shift;
my $base = shift; $base = "esp" if (!defined($base));

	################################################################
	# As for choice to "rotate" $T0-$T2 in order to move paddq
	# past next multiplication. While it makes code harder to read
	# and doesn't have significant effect on most processors, it
	# makes a lot of difference on Atom, up to 30% improvement.

	&movdqa		($T1,$T0);
	&pmuludq	($T0,&QWP(16*3,$base));		# r1*h3
	&movdqa		($T2,$T1);
	&pmuludq	($T1,&QWP(16*2,$base));		# r1*h2
	&paddq		($D4,$T0);
	&movdqa		($T0,$T2);
	&pmuludq	($T2,&QWP(16*1,$base));		# r1*h1
	&paddq		($D3,$T1);
	&$load		($T1,5);			# s1
	&pmuludq	($T0,&QWP(16*0,$base));		# r1*h0
	&paddq		($D2,$T2);
	&pmuludq	($T1,&QWP(16*4,$base));		# s1*h4
	 &$load		($T2,2);			# r2^n
	&paddq		($D1,$T0);

	&movdqa		($T0,$T2);
	&pmuludq	($T2,&QWP(16*2,$base));		# r2*h2
	 &paddq		($D0,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&QWP(16*1,$base));		# r2*h1
	&paddq		($D4,$T2);
	&$load		($T2,6);			# s2^n
	&pmuludq	($T1,&QWP(16*0,$base));		# r2*h0
	&paddq		($D3,$T0);
	&movdqa		($T0,$T2);
	&pmuludq	($T2,&QWP(16*4,$base));		# s2*h4
	&paddq		($D2,$T1);
	&pmuludq	($T0,&QWP(16*3,$base));		# s2*h3
	 &$load		($T1,3);			# r3^n
	&paddq		($D1,$T2);

	&movdqa		($T2,$T1);
	&pmuludq	($T1,&QWP(16*1,$base));		# r3*h1
	 &paddq		($D0,$T0);
	&$load		($T0,7);			# s3^n
	&pmuludq	($T2,&QWP(16*0,$base));		# r3*h0
	&paddq		($D4,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&QWP(16*4,$base));		# s3*h4
	&paddq		($D3,$T2);
	&movdqa		($T2,$T1);
	&pmuludq	($T1,&QWP(16*3,$base));		# s3*h3
	&paddq		($D2,$T0);
	&pmuludq	($T2,&QWP(16*2,$base));		# s3*h2
	 &$load		($T0,4);			# r4^n
	&paddq		($D1,$T1);

	&$load		($T1,8);			# s4^n
	&pmuludq	($T0,&QWP(16*0,$base));		# r4*h0
	 &paddq		($D0,$T2);
	&movdqa		($T2,$T1);
	&pmuludq	($T1,&QWP(16*4,$base));		# s4*h4
	&paddq		($D4,$T0);
	&movdqa		($T0,$T2);
	&pmuludq	($T2,&QWP(16*1,$base));		# s4*h1
	&paddq		($D3,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&QWP(16*2,$base));		# s4*h2
	&paddq		($D0,$T2);
	&pmuludq	($T1,&QWP(16*3,$base));		# s4*h3
	 &movdqa	($MASK,&QWP(64,"ebx"));
	&paddq		($D1,$T0);
	&paddq		($D2,$T1);
}
	&pmuladd	(sub {	my ($reg,$i)=@_;
				&movdqa ($reg,&QWP(16*$i,"esp"));
			     },"edx");

sub lazy_reduction {
my $extra = shift;

	################################################################
	# lazy reduction as discussed in "NEON crypto" by D.J. Bernstein
	# and P. Schwabe
	#
	# [(*) see discussion in poly1305-armv4 module]

	 &movdqa	($T0,$D3);
	 &pand		($D3,$MASK);
	 &psrlq		($T0,26);
	 &$extra	()				if (defined($extra));
	 &paddq		($T0,$D4);			# h3 -> h4
	&movdqa		($T1,$D0);
	&pand		($D0,$MASK);
	&psrlq		($T1,26);
	 &movdqa	($D4,$T0);
	&paddq		($T1,$D1);			# h0 -> h1
	 &psrlq		($T0,26);
	 &pand		($D4,$MASK);
	&movdqa		($D1,$T1);
	&psrlq		($T1,26);
	 &paddd		($D0,$T0);			# favour paddd when
							# possible, because
							# paddq is "broken"
							# on Atom
	 &psllq		($T0,2);
	&paddq		($T1,$D2);			# h1 -> h2
	 &paddq		($T0,$D0);			# h4 -> h0 (*)
	&pand		($D1,$MASK);
	&movdqa		($D2,$T1);
	&psrlq		($T1,26);
	&pand		($D2,$MASK);
	&paddd		($T1,$D3);			# h2 -> h3
	 &movdqa	($D0,$T0);
	 &psrlq		($T0,26);
	&movdqa		($D3,$T1);
	&psrlq		($T1,26);
	 &pand		($D0,$MASK);
	 &paddd		($D1,$T0);			# h0 -> h1
	&pand		($D3,$MASK);
	&paddd		($D4,$T1);			# h3 -> h4
}
	&lazy_reduction	();

	&dec		("ecx");
	&jz		(&label("square_break"));

	&punpcklqdq	($D0,&QWP(16*0,"esp"));		# 0:r^1:0:r^2
	&punpcklqdq	($D1,&QWP(16*1,"esp"));
	&punpcklqdq	($D2,&QWP(16*2,"esp"));
	&punpcklqdq	($D3,&QWP(16*3,"esp"));
	&punpcklqdq	($D4,&QWP(16*4,"esp"));
	&jmp		(&label("square"));

&set_label("square_break");
	&psllq		($D0,32);			# -> r^3:0:r^4:0
	&psllq		($D1,32);
	&psllq		($D2,32);
	&psllq		($D3,32);
	&psllq		($D4,32);
	&por		($D0,&QWP(16*0,"esp"));		# r^3:r^1:r^4:r^2
	&por		($D1,&QWP(16*1,"esp"));
	&por		($D2,&QWP(16*2,"esp"));
	&por		($D3,&QWP(16*3,"esp"));
	&por		($D4,&QWP(16*4,"esp"));

	&pshufd		($D0,$D0,0b10001101);		# -> r^1:r^2:r^3:r^4
	&pshufd		($D1,$D1,0b10001101);
	&pshufd		($D2,$D2,0b10001101);
	&pshufd		($D3,$D3,0b10001101);
	&pshufd		($D4,$D4,0b10001101);

	&movdqu		(&QWP(16*0,"edi"),$D0);		# save the table
	&movdqu		(&QWP(16*1,"edi"),$D1);
	&movdqu		(&QWP(16*2,"edi"),$D2);
	&movdqu		(&QWP(16*3,"edi"),$D3);
	&movdqu		(&QWP(16*4,"edi"),$D4);

	&movdqa		($T1,$D1);
	&movdqa		($T0,$D2);
	&pslld		($T1,2);
	&pslld		($T0,2);
	&paddd		($T1,$D1);			# *5
	&paddd		($T0,$D2);			# *5
	&movdqu		(&QWP(16*5,"edi"),$T1);
	&movdqu		(&QWP(16*6,"edi"),$T0);
	&movdqa		($T1,$D3);
	&movdqa		($T0,$D4);
	&pslld		($T1,2);
	&pslld		($T0,2);
	&paddd		($T1,$D3);			# *5
	&paddd		($T0,$D4);			# *5
	&movdqu		(&QWP(16*7,"edi"),$T1);
	&movdqu		(&QWP(16*8,"edi"),$T0);

	&mov		("esp","ebp");
	&lea		("edi",&DWP(-16*3,"edi"));	# size de-optimization
	&ret		();
&function_end_B("_poly1305_init_sse2");

&align	(32);
&function_begin("_poly1305_blocks_sse2");
	&mov	("edi",&wparam(0));			# ctx
	&mov	("esi",&wparam(1));			# inp
	&mov	("ecx",&wparam(2));			# len

	&mov	("eax",&DWP(4*5,"edi"));		# is_base2_26
	&and	("ecx",-16);
	&jz	(&label("nodata"));
	&cmp	("ecx",64);
	&jae	(&label("enter_sse2"));
	&test	("eax","eax");				# is_base2_26?
	&jz	(&label("enter_blocks"));

&set_label("enter_sse2",16);
	&call	(&label("pic_point"));
&set_label("pic_point");
	&blindpop("ebx");
	&lea	("ebx",&DWP(&label("const_sse2")."-".&label("pic_point"),"ebx"));

	&test	("eax","eax");				# is_base2_26?
	&jnz	(&label("base2_26"));

	&call	("_poly1305_init_sse2");

	################################################# base 2^32 -> base 2^26
	&mov	("eax",&DWP(0,"edi"));
	&mov	("ecx",&DWP(3,"edi"));
	&mov	("edx",&DWP(6,"edi"));
	&mov	("esi",&DWP(9,"edi"));
	&mov	("ebp",&DWP(13,"edi"));
	&mov	(&DWP(4*5,"edi"),1);			# is_base2_26

	&shr	("ecx",2);
	&and	("eax",0x3ffffff);
	&shr	("edx",4);
	&and	("ecx",0x3ffffff);
	&shr	("esi",6);
	&and	("edx",0x3ffffff);

	&movd	($D0,"eax");
	&movd	($D1,"ecx");
	&movd	($D2,"edx");
	&movd	($D3,"esi");
	&movd	($D4,"ebp");

	&mov	("esi",&wparam(1));			# [reload] inp
	&mov	("ecx",&wparam(2));			# [reload] len
	&jmp	(&label("base2_32"));

&set_label("base2_26",16);
	&movd	($D0,&DWP(4*0,"edi"));			# load hash value
	&movd	($D1,&DWP(4*1,"edi"));
	&movd	($D2,&DWP(4*2,"edi"));
	&movd	($D3,&DWP(4*3,"edi"));
	&movd	($D4,&DWP(4*4,"edi"));
	&movdqa	($MASK,&QWP(64,"ebx"));

&set_label("base2_32");
	&mov	("eax",&wparam(3));			# padbit
	&mov	("ebp","esp");

	&sub	("esp",16*(5+5+5+9+9));
	&and	("esp",-16);

	&lea	("edi",&DWP(16*3,"edi"));		# size optimization
	&shl	("eax",24);				# padbit

	&test	("ecx",31);
	&jz	(&label("even"));

	################################################################
	# process single block, with SSE2, because it's still faster
	# even though half of result is discarded

	&movdqu		($T1,&QWP(0,"esi"));		# input
	&lea		("esi",&DWP(16,"esi"));

	&movdqa		($T0,$T1);			# -> base 2^26 ...
	&pand		($T1,$MASK);
	&paddd		($D0,$T1);			# ... and accumuate

	&movdqa		($T1,$T0);
	&psrlq		($T0,26);
	&psrldq		($T1,6);
	&pand		($T0,$MASK);
	&paddd		($D1,$T0);

	&movdqa		($T0,$T1);
	&psrlq		($T1,4);
	&pand		($T1,$MASK);
	&paddd		($D2,$T1);

	&movdqa		($T1,$T0);
	&psrlq		($T0,30);
	&pand		($T0,$MASK);
	&psrldq		($T1,7);
	&paddd		($D3,$T0);

	&movd		($T0,"eax");			# padbit
	&paddd		($D4,$T1);
	 &movd		($T1,&DWP(16*0+12,"edi"));	# r0
	&paddd		($D4,$T0);

	&movdqa		(&QWP(16*0,"esp"),$D0);
	&movdqa		(&QWP(16*1,"esp"),$D1);
	&movdqa		(&QWP(16*2,"esp"),$D2);
	&movdqa		(&QWP(16*3,"esp"),$D3);
	&movdqa		(&QWP(16*4,"esp"),$D4);

	################################################################
	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4

	&pmuludq	($D0,$T1);			# h4*r0
	&pmuludq	($D1,$T1);			# h3*r0
	&pmuludq	($D2,$T1);			# h2*r0
	 &movd		($T0,&DWP(16*1+12,"edi"));	# r1
	&pmuludq	($D3,$T1);			# h1*r0
	&pmuludq	($D4,$T1);			# h0*r0

	&pmuladd	(sub {	my ($reg,$i)=@_;
				&movd ($reg,&DWP(16*$i+12,"edi"));
			     });

	&lazy_reduction	();

	&sub		("ecx",16);
	&jz		(&label("done"));

&set_label("even");
	&lea		("edx",&DWP(16*(5+5+5+9),"esp"));# size optimization
	&lea		("eax",&DWP(-16*2,"esi"));
	&sub		("ecx",64);

	################################################################
	# expand and copy pre-calculated table to stack

	&movdqu		($T0,&QWP(16*0,"edi"));		# r^1:r^2:r^3:r^4
	&pshufd		($T1,$T0,0b01000100);		# duplicate r^3:r^4
	&cmovb		("esi","eax");
	&pshufd		($T0,$T0,0b11101110);		# duplicate r^1:r^2
	&movdqa		(&QWP(16*0,"edx"),$T1);
	&lea		("eax",&DWP(16*10,"esp"));
	&movdqu		($T1,&QWP(16*1,"edi"));
	&movdqa		(&QWP(16*(0-9),"edx"),$T0);
	&pshufd		($T0,$T1,0b01000100);
	&pshufd		($T1,$T1,0b11101110);
	&movdqa		(&QWP(16*1,"edx"),$T0);
	&movdqu		($T0,&QWP(16*2,"edi"));
	&movdqa		(&QWP(16*(1-9),"edx"),$T1);
	&pshufd		($T1,$T0,0b01000100);
	&pshufd		($T0,$T0,0b11101110);
	&movdqa		(&QWP(16*2,"edx"),$T1);
	&movdqu		($T1,&QWP(16*3,"edi"));
	&movdqa		(&QWP(16*(2-9),"edx"),$T0);
	&pshufd		($T0,$T1,0b01000100);
	&pshufd		($T1,$T1,0b11101110);
	&movdqa		(&QWP(16*3,"edx"),$T0);
	&movdqu		($T0,&QWP(16*4,"edi"));
	&movdqa		(&QWP(16*(3-9),"edx"),$T1);
	&pshufd		($T1,$T0,0b01000100);
	&pshufd		($T0,$T0,0b11101110);
	&movdqa		(&QWP(16*4,"edx"),$T1);
	&movdqu		($T1,&QWP(16*5,"edi"));
	&movdqa		(&QWP(16*(4-9),"edx"),$T0);
	&pshufd		($T0,$T1,0b01000100);
	&pshufd		($T1,$T1,0b11101110);
	&movdqa		(&QWP(16*5,"edx"),$T0);
	&movdqu		($T0,&QWP(16*6,"edi"));
	&movdqa		(&QWP(16*(5-9),"edx"),$T1);
	&pshufd		($T1,$T0,0b01000100);
	&pshufd		($T0,$T0,0b11101110);
	&movdqa		(&QWP(16*6,"edx"),$T1);
	&movdqu		($T1,&QWP(16*7,"edi"));
	&movdqa		(&QWP(16*(6-9),"edx"),$T0);
	&pshufd		($T0,$T1,0b01000100);
	&pshufd		($T1,$T1,0b11101110);
	&movdqa		(&QWP(16*7,"edx"),$T0);
	&movdqu		($T0,&QWP(16*8,"edi"));
	&movdqa		(&QWP(16*(7-9),"edx"),$T1);
	&pshufd		($T1,$T0,0b01000100);
	&pshufd		($T0,$T0,0b11101110);
	&movdqa		(&QWP(16*8,"edx"),$T1);
	&movdqa		(&QWP(16*(8-9),"edx"),$T0);

sub load_input {
my ($inpbase,$offbase)=@_;

	&movdqu		($T0,&QWP($inpbase+0,"esi"));	# load input
	&movdqu		($T1,&QWP($inpbase+16,"esi"));
	&lea		("esi",&DWP(16*2,"esi"));

	&movdqa		(&QWP($offbase+16*2,"esp"),$D2);
	&movdqa		(&QWP($offbase+16*3,"esp"),$D3);
	&movdqa		(&QWP($offbase+16*4,"esp"),$D4);

	&movdqa		($D2,$T0);			# splat input
	&movdqa		($D3,$T1);
	&psrldq		($D2,6);
	&psrldq		($D3,6);
	&movdqa		($D4,$T0);
	&punpcklqdq	($D2,$D3);			# 2:3
	&punpckhqdq	($D4,$T1);			# 4
	&punpcklqdq	($T0,$T1);			# 0:1

	&movdqa		($D3,$D2);
	&psrlq		($D2,4);
	&psrlq		($D3,30);
	&movdqa		($T1,$T0);
	&psrlq		($D4,40);			# 4
	&psrlq		($T1,26);
	&pand		($T0,$MASK);			# 0
	&pand		($T1,$MASK);			# 1
	&pand		($D2,$MASK);			# 2
	&pand		($D3,$MASK);			# 3
	&por		($D4,&QWP(0,"ebx"));		# padbit, yes, always

	&movdqa		(&QWP($offbase+16*0,"esp"),$D0)	if ($offbase);
	&movdqa		(&QWP($offbase+16*1,"esp"),$D1)	if ($offbase);
}
	&load_input	(16*2,16*5);

	&jbe		(&label("skip_loop"));
	&jmp		(&label("loop"));

&set_label("loop",32);
	################################################################
	# ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2
	# ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^3+inp[7]*r
	#   \___________________/
	# ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2+inp[8])*r^2
	# ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^4+inp[7]*r^2+inp[9])*r
	#   \___________________/ \____________________/
	################################################################

	&movdqa		($T2,&QWP(16*(0-9),"edx"));	# r0^2
	&movdqa		(&QWP(16*1,"eax"),$T1);
	&movdqa		(&QWP(16*2,"eax"),$D2);
	&movdqa		(&QWP(16*3,"eax"),$D3);
	&movdqa		(&QWP(16*4,"eax"),$D4);

	################################################################
	# d4 = h4*r0 + h0*r4   + h1*r3   + h2*r2   + h3*r1
	# d3 = h3*r0 + h0*r3   + h1*r2   + h2*r1   + h4*5*r4
	# d2 = h2*r0 + h0*r2   + h1*r1   + h3*5*r4 + h4*5*r3
	# d1 = h1*r0 + h0*r1   + h2*5*r4 + h3*5*r3 + h4*5*r2
	# d0 = h0*r0 + h1*5*r4 + h2*5*r3 + h3*5*r2 + h4*5*r1

	&movdqa		($D1,$T0);
	&pmuludq	($T0,$T2);			# h0*r0
	&movdqa		($D0,$T1);
	&pmuludq	($T1,$T2);			# h1*r0
	&pmuludq	($D2,$T2);			# h2*r0
	&pmuludq	($D3,$T2);			# h3*r0
	&pmuludq	($D4,$T2);			# h4*r0

sub pmuladd_alt {
my $addr = shift;

	&pmuludq	($D0,&$addr(8));		# h1*s4
	&movdqa		($T2,$D1);
	&pmuludq	($D1,&$addr(1));		# h0*r1
	&paddq		($D0,$T0);
	&movdqa		($T0,$T2);
	&pmuludq	($T2,&$addr(2));		# h0*r2
	&paddq		($D1,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&$addr(3));		# h0*r3
	&paddq		($D2,$T2);
	 &movdqa	($T2,&QWP(16*1,"eax"));		# pull h1
	&pmuludq	($T1,&$addr(4));		# h0*r4
	&paddq		($D3,$T0);

	&movdqa		($T0,$T2);
	&pmuludq	($T2,&$addr(1));		# h1*r1
	 &paddq		($D4,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&$addr(2));		# h1*r2
	&paddq		($D2,$T2);
	&movdqa		($T2,&QWP(16*2,"eax"));		# pull h2
	&pmuludq	($T1,&$addr(3));		# h1*r3
	&paddq		($D3,$T0);
	&movdqa		($T0,$T2);
	&pmuludq	($T2,&$addr(7));		# h2*s3
	&paddq		($D4,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&$addr(8));		# h2*s4
	&paddq		($D0,$T2);

	&movdqa		($T2,$T1);
	&pmuludq	($T1,&$addr(1));		# h2*r1
	 &paddq		($D1,$T0);
	&movdqa		($T0,&QWP(16*3,"eax"));		# pull h3
	&pmuludq	($T2,&$addr(2));		# h2*r2
	&paddq		($D3,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&$addr(6));		# h3*s2
	&paddq		($D4,$T2);
	&movdqa		($T2,$T1);
	&pmuludq	($T1,&$addr(7));		# h3*s3
	&paddq		($D0,$T0);
	&movdqa		($T0,$T2);
	&pmuludq	($T2,&$addr(8));		# h3*s4
	&paddq		($D1,$T1);

	&movdqa		($T1,&QWP(16*4,"eax"));		# pull h4
	&pmuludq	($T0,&$addr(1));		# h3*r1
	 &paddq		($D2,$T2);
	&movdqa		($T2,$T1);
	&pmuludq	($T1,&$addr(8));		# h4*s4
	&paddq		($D4,$T0);
	&movdqa		($T0,$T2);
	&pmuludq	($T2,&$addr(5));		# h4*s1
	&paddq		($D3,$T1);
	&movdqa		($T1,$T0);
	&pmuludq	($T0,&$addr(6));		# h4*s2
	&paddq		($D0,$T2);
	 &movdqa	($MASK,&QWP(64,"ebx"));
	&pmuludq	($T1,&$addr(7));		# h4*s3
	&paddq		($D1,$T0);
	&paddq		($D2,$T1);
}
	&pmuladd_alt	(sub {	my $i=shift; &QWP(16*($i-9),"edx");	});

	&load_input	(-16*2,0);
	&lea		("eax",&DWP(-16*2,"esi"));
	&sub		("ecx",64);

	&paddd		($T0,&QWP(16*(5+0),"esp"));	# add hash value
	&paddd		($T1,&QWP(16*(5+1),"esp"));
	&paddd		($D2,&QWP(16*(5+2),"esp"));
	&paddd		($D3,&QWP(16*(5+3),"esp"));
	&paddd		($D4,&QWP(16*(5+4),"esp"));

	&cmovb		("esi","eax");
	&lea		("eax",&DWP(16*10,"esp"));

	&movdqa		($T2,&QWP(16*0,"edx"));		# r0^4
	&movdqa		(&QWP(16*1,"esp"),$D1);
	&movdqa		(&QWP(16*1,"eax"),$T1);
	&movdqa		(&QWP(16*2,"eax"),$D2);
	&movdqa		(&QWP(16*3,"eax"),$D3);
	&movdqa		(&QWP(16*4,"eax"),$D4);

	################################################################
	# d4 += h4*r0 + h0*r4   + h1*r3   + h2*r2   + h3*r1
	# d3 += h3*r0 + h0*r3   + h1*r2   + h2*r1   + h4*5*r4
	# d2 += h2*r0 + h0*r2   + h1*r1   + h3*5*r4 + h4*5*r3
	# d1 += h1*r0 + h0*r1   + h2*5*r4 + h3*5*r3 + h4*5*r2
	# d0 += h0*r0 + h1*5*r4 + h2*5*r3 + h3*5*r2 + h4*5*r1

	&movdqa		($D1,$T0);
	&pmuludq	($T0,$T2);			# h0*r0
	&paddq		($T0,$D0);
	&movdqa		($D0,$T1);
	&pmuludq	($T1,$T2);			# h1*r0
	&pmuludq	($D2,$T2);			# h2*r0
	&pmuludq	($D3,$T2);			# h3*r0
	&pmuludq	($D4,$T2);			# h4*r0

	&paddq		($T1,&QWP(16*1,"esp"));
	&paddq		($D2,&QWP(16*2,"esp"));
	&paddq		($D3,&QWP(16*3,"esp"));
	&paddq		($D4,&QWP(16*4,"esp"));

	&pmuladd_alt	(sub {	my $i=shift; &QWP(16*$i,"edx");	});

	&lazy_reduction	();

	&load_input	(16*2,16*5);

	&ja		(&label("loop"));

&set_label("skip_loop");
	################################################################
	# multiply (inp[0:1]+hash) or inp[2:3] by r^2:r^1

	 &pshufd	($T2,&QWP(16*(0-9),"edx"),0x10);# r0^n
	&add		("ecx",32);
	&jnz		(&label("long_tail"));

	&paddd		($T0,$D0);			# add hash value
	&paddd		($T1,$D1);
	&paddd		($D2,&QWP(16*7,"esp"));
	&paddd		($D3,&QWP(16*8,"esp"));
	&paddd		($D4,&QWP(16*9,"esp"));

&set_label("long_tail");

	&movdqa		(&QWP(16*0,"eax"),$T0);
	&movdqa		(&QWP(16*1,"eax"),$T1);
	&movdqa		(&QWP(16*2,"eax"),$D2);
	&movdqa		(&QWP(16*3,"eax"),$D3);
	&movdqa		(&QWP(16*4,"eax"),$D4);

	################################################################
	# d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	# d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	# d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	# d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	# d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4

	&pmuludq	($T0,$T2);			# h0*r0
	&pmuludq	($T1,$T2);			# h1*r0
	&pmuludq	($D2,$T2);			# h2*r0
	&movdqa		($D0,$T0);
	 &pshufd	($T0,&QWP(16*(1-9),"edx"),0x10);# r1^n
	&pmuludq	($D3,$T2);			# h3*r0
	&movdqa		($D1,$T1);
	&pmuludq	($D4,$T2);			# h4*r0

	&pmuladd	(sub {	my ($reg,$i)=@_;
				&pshufd ($reg,&QWP(16*($i-9),"edx"),0x10);
			     },"eax");

	&jz		(&label("short_tail"));

	&load_input	(-16*2,0);

	 &pshufd	($T2,&QWP(16*0,"edx"),0x10);	# r0^n
	&paddd		($T0,&QWP(16*5,"esp"));		# add hash value
	&paddd		($T1,&QWP(16*6,"esp"));
	&paddd		($D2,&QWP(16*7,"esp"));
	&paddd		($D3,&QWP(16*8,"esp"));
	&paddd		($D4,&QWP(16*9,"esp"));

	################################################################
	# multiply inp[0:1] by r^4:r^3 and accumulate

	&movdqa		(&QWP(16*0,"esp"),$T0);
	&pmuludq	($T0,$T2);			# h0*r0
	&movdqa		(&QWP(16*1,"esp"),$T1);
	&pmuludq	($T1,$T2);			# h1*r0
	&paddq		($D0,$T0);
	&movdqa		($T0,$D2);
	&pmuludq	($D2,$T2);			# h2*r0
	&paddq		($D1,$T1);
	&movdqa		($T1,$D3);
	&pmuludq	($D3,$T2);			# h3*r0
	&paddq		($D2,&QWP(16*2,"esp"));
	&movdqa		(&QWP(16*2,"esp"),$T0);
	 &pshufd	($T0,&QWP(16*1,"edx"),0x10);	# r1^n
	&paddq		($D3,&QWP(16*3,"esp"));
	&movdqa		(&QWP(16*3,"esp"),$T1);
	&movdqa		($T1,$D4);
	&pmuludq	($D4,$T2);			# h4*r0
	&paddq		($D4,&QWP(16*4,"esp"));
	&movdqa		(&QWP(16*4,"esp"),$T1);

	&pmuladd	(sub {	my ($reg,$i)=@_;
				&pshufd ($reg,&QWP(16*$i,"edx"),0x10);
			     });

&set_label("short_tail");

	################################################################
	# horizontal addition

	&pshufd		($T1,$D4,0b01001110);
	&pshufd		($T0,$D3,0b01001110);
	&paddq		($D4,$T1);
	&paddq		($D3,$T0);
	&pshufd		($T1,$D0,0b01001110);
	&pshufd		($T0,$D1,0b01001110);
	&paddq		($D0,$T1);
	&paddq		($D1,$T0);
	&pshufd		($T1,$D2,0b01001110);
	#&paddq		($D2,$T1);

	&lazy_reduction	(sub { &paddq ($D2,$T1) });

&set_label("done");
	&movd		(&DWP(-16*3+4*0,"edi"),$D0);	# store hash value
	&movd		(&DWP(-16*3+4*1,"edi"),$D1);
	&movd		(&DWP(-16*3+4*2,"edi"),$D2);
	&movd		(&DWP(-16*3+4*3,"edi"),$D3);
	&movd		(&DWP(-16*3+4*4,"edi"),$D4);
	&mov	("esp","ebp");
&set_label("nodata");
&function_end("_poly1305_blocks_sse2");

&align	(32);
&function_begin("_poly1305_emit_sse2");
	&mov	("ebp",&wparam(0));		# context

	&cmp	(&DWP(4*5,"ebp"),0);		# is_base2_26?
	&je	(&label("enter_emit"));

	&mov	("eax",&DWP(4*0,"ebp"));	# load hash value
	&mov	("edi",&DWP(4*1,"ebp"));
	&mov	("ecx",&DWP(4*2,"ebp"));
	&mov	("edx",&DWP(4*3,"ebp"));
	&mov	("esi",&DWP(4*4,"ebp"));

	&mov	("ebx","edi");			# base 2^26 -> base 2^32
	&shl	("edi",26);
	&shr	("ebx",6);
	&add	("eax","edi");
	&mov	("edi","ecx");
	&adc	("ebx",0);

	&shl	("edi",20);
	&shr	("ecx",12);
	&add	("ebx","edi");
	&mov	("edi","edx");
	&adc	("ecx",0);

	&shl	("edi",14);
	&shr	("edx",18);
	&add	("ecx","edi");
	&mov	("edi","esi");
	&adc	("edx",0);

	&shl	("edi",8);
	&shr	("esi",24);
	&add	("edx","edi");
	&adc	("esi",0);			# can be partially reduced

	&mov	("edi","esi");			# final reduction
	&and	("esi",3);
	&shr	("edi",2);
	&lea	("ebp",&DWP(0,"edi","edi",4));	# *5
	 &mov	("edi",&wparam(1));		# output
	&add	("eax","ebp");
	 &mov	("ebp",&wparam(2));		# key
	&adc	("ebx",0);
	&adc	("ecx",0);
	&adc	("edx",0);
	&adc	("esi",0);

	&movd	($D0,"eax");			# offload original hash value
	&add	("eax",5);			# compare to modulus
	&movd	($D1,"ebx");
	&adc	("ebx",0);
	&movd	($D2,"ecx");
	&adc	("ecx",0);
	&movd	($D3,"edx");
	&adc	("edx",0);
	&adc	("esi",0);
	&shr	("esi",2);			# did it carry/borrow?

	&neg	("esi");			# do we choose (hash-modulus) ...
	&and	("eax","esi");
	&and	("ebx","esi");
	&and	("ecx","esi");
	&and	("edx","esi");
	&mov	(&DWP(4*0,"edi"),"eax");
	&movd	("eax",$D0);
	&mov	(&DWP(4*1,"edi"),"ebx");
	&movd	("ebx",$D1);
	&mov	(&DWP(4*2,"edi"),"ecx");
	&movd	("ecx",$D2);
	&mov	(&DWP(4*3,"edi"),"edx");
	&movd	("edx",$D3);

	&not	("esi");			# ... or original hash value?
	&and	("eax","esi");
	&and	("ebx","esi");
	&or	("eax",&DWP(4*0,"edi"));
	&and	("ecx","esi");
	&or	("ebx",&DWP(4*1,"edi"));
	&and	("edx","esi");
	&or	("ecx",&DWP(4*2,"edi"));
	&or	("edx",&DWP(4*3,"edi"));

	&add	("eax",&DWP(4*0,"ebp"));	# accumulate key
	&adc	("ebx",&DWP(4*1,"ebp"));
	&mov	(&DWP(4*0,"edi"),"eax");
	&adc	("ecx",&DWP(4*2,"ebp"));
	&mov	(&DWP(4*1,"edi"),"ebx");
	&adc	("edx",&DWP(4*3,"ebp"));
	&mov	(&DWP(4*2,"edi"),"ecx");
	&mov	(&DWP(4*3,"edi"),"edx");
&function_end("_poly1305_emit_sse2");

# The AVX2 code was removed.

&set_label("const_sse2",64);
	&data_word(1<<24,0,	1<<24,0,	1<<24,0,	1<<24,0);
	&data_word(0,0,		0,0,		0,0,		0,0);
	&data_word(0x03ffffff,0,0x03ffffff,0,	0x03ffffff,0,	0x03ffffff,0);
	&data_word(0x0fffffff,0x0ffffffc,0x0ffffffc,0x0ffffffc);
}
&asciz	("Poly1305 for x86, CRYPTOGAMS by <appro\@openssl.org>");
&align	(4);

&asm_finish();

close STDOUT;
