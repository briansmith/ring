#! /usr/bin/env perl
# Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# Version 2.1.
#
# aes-*-cbc benchmarks are improved by >70% [compared to gcc 3.3.2 on
# Opteron 240 CPU] plus all the bells-n-whistles from 32-bit version
# [you'll notice a lot of resemblance], such as compressed S-boxes
# in little-endian byte order, prefetch of these tables in CBC mode,
# as well as avoiding L1 cache aliasing between stack frame and key
# schedule and already mentioned tables, compressed Td4...
#
# Performance in number of cycles per processed byte for 128-bit key:
#
#		ECB encrypt	ECB decrypt	CBC large chunk
# AMD64		33		43		13.0
# EM64T		38		56		18.6(*)
# Core 2	30		42		14.5(*)
# Atom		65		86		32.1(*)
#
# (*) with hyper-threading off

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

$verticalspin=1;	# unlike 32-bit version $verticalspin performs
			# ~15% better on both AMD and Intel cores
$speed_limit=512;	# see aes-586.pl for details

$code=".text\n";

$s0="%eax";
$s1="%ebx";
$s2="%ecx";
$s3="%edx";
$acc0="%esi";	$mask80="%rsi";
$acc1="%edi";	$maskfe="%rdi";
$acc2="%ebp";	$mask1b="%rbp";
$inp="%r8";
$out="%r9";
$t0="%r10d";
$t1="%r11d";
$t2="%r12d";
$rnds="%r13d";
$sbox="%r14";
$key="%r15";

sub hi() { my $r=shift;	$r =~ s/%[er]([a-d])x/%\1h/;	$r; }
sub lo() { my $r=shift;	$r =~ s/%[er]([a-d])x/%\1l/;
			$r =~ s/%[er]([sd]i)/%\1l/;
			$r =~ s/%(r[0-9]+)[d]?/%\1b/;	$r; }
sub LO() { my $r=shift; $r =~ s/%r([a-z]+)/%e\1/;
			$r =~ s/%r([0-9]+)/%r\1d/;	$r; }
sub _data_word()
{ my $i;
    while(defined($i=shift)) { $code.=sprintf".long\t0x%08x,0x%08x\n",$i,$i; }
}
sub data_word()
{ my $i;
  my $last=pop(@_);
    $code.=".long\t";
    while(defined($i=shift)) { $code.=sprintf"0x%08x,",$i; }
    $code.=sprintf"0x%08x\n",$last;
}

sub data_byte()
{ my $i;
  my $last=pop(@_);
    $code.=".byte\t";
    while(defined($i=shift)) { $code.=sprintf"0x%02x,",$i&0xff; }
    $code.=sprintf"0x%02x\n",$last&0xff;
}

sub encvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	# favor 3-way issue Opteron pipeline...
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	mov	0($sbox,$acc0,8),$t0
	mov	0($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t2

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	movzb	`&lo("$s3")`,$acc2
	xor	3($sbox,$acc0,8),$t0
	xor	3($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t3

	movzb	`&hi("$s3")`,$acc0
	shr	\$16,$s2
	movzb	`&hi("$s0")`,$acc2
	xor	3($sbox,$acc0,8),$t2
	shr	\$16,$s3
	xor	3($sbox,$acc2,8),$t3

	shr	\$16,$s1
	lea	16($key),$key
	shr	\$16,$s0

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	xor	2($sbox,$acc0,8),$t0
	xor	2($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	movzb	`&lo("$s1")`,$acc2
	xor	1($sbox,$acc0,8),$t0
	xor	1($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t3

	mov	12($key),$s3
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	mov	0($key),$s0
	xor	1($sbox,$acc1,8),$t2
	xor	1($sbox,$acc2,8),$t3

	mov	4($key),$s1
	mov	8($key),$s2
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub enclastvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	movzb	2($sbox,$acc0,8),$t0
	movzb	2($sbox,$acc1,8),$t1
	movzb	2($sbox,$acc2,8),$t2

	movzb	`&lo("$s3")`,$acc0
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	movzb	2($sbox,$acc0,8),$t3
	mov	0($sbox,$acc1,8),$acc1	#$t0
	mov	0($sbox,$acc2,8),$acc2	#$t1

	and	\$0x0000ff00,$acc1
	and	\$0x0000ff00,$acc2

	xor	$acc1,$t0
	xor	$acc2,$t1
	shr	\$16,$s2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	shr	\$16,$s3
	mov	0($sbox,$acc0,8),$acc0	#$t2
	mov	0($sbox,$acc1,8),$acc1	#$t3

	and	\$0x0000ff00,$acc0
	and	\$0x0000ff00,$acc1
	shr	\$16,$s1
	xor	$acc0,$t2
	xor	$acc1,$t3
	shr	\$16,$s0

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	mov	0($sbox,$acc0,8),$acc0	#$t0
	mov	0($sbox,$acc1,8),$acc1	#$t1
	mov	0($sbox,$acc2,8),$acc2	#$t2

	and	\$0x00ff0000,$acc0
	and	\$0x00ff0000,$acc1
	and	\$0x00ff0000,$acc2

	xor	$acc0,$t0
	xor	$acc1,$t1
	xor	$acc2,$t2

	movzb	`&lo("$s1")`,$acc0
	movzb	`&hi("$s3")`,$acc1
	movzb	`&hi("$s0")`,$acc2
	mov	0($sbox,$acc0,8),$acc0	#$t3
	mov	2($sbox,$acc1,8),$acc1	#$t0
	mov	2($sbox,$acc2,8),$acc2	#$t1

	and	\$0x00ff0000,$acc0
	and	\$0xff000000,$acc1
	and	\$0xff000000,$acc2

	xor	$acc0,$t3
	xor	$acc1,$t0
	xor	$acc2,$t1

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	mov	16+12($key),$s3
	mov	2($sbox,$acc0,8),$acc0	#$t2
	mov	2($sbox,$acc1,8),$acc1	#$t3
	mov	16+0($key),$s0

	and	\$0xff000000,$acc0
	and	\$0xff000000,$acc1

	xor	$acc0,$t2
	xor	$acc1,$t3

	mov	16+4($key),$s1
	mov	16+8($key),$s2
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub encstep()
{ my ($i,@s) = @_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	if ($i==3) {
		$tmp0=$s[1];
		$tmp1=$s[2];
		$tmp2=$s[3];
	}
	$code.="	movzb	".&lo($s[0]).",$out\n";
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);
	$code.="	lea	16($key),$key\n"	if ($i==0);

	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	mov	0($sbox,$out,8),$out\n";

	$code.="	shr	\$16,$tmp1\n";
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);
	$code.="	xor	3($sbox,$tmp0,8),$out\n";

	$code.="	movzb	".&lo($tmp1).",$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";
	$code.="	xor	4*$i($key),$out\n";

	$code.="	xor	2($sbox,$tmp1,8),$out\n";
	$code.="	xor	1($sbox,$tmp2,8),$out\n";

	$code.="	mov	$t0,$s[1]\n"		if ($i==3);
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	mov	$t2,$s[3]\n"		if ($i==3);
	$code.="\n";
}

sub enclast()
{ my ($i,@s)=@_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	if ($i==3) {
		$tmp0=$s[1];
		$tmp1=$s[2];
		$tmp2=$s[3];
	}
	$code.="	movzb	".&lo($s[0]).",$out\n";
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);

	$code.="	mov	2($sbox,$out,8),$out\n";
	$code.="	shr	\$16,$tmp1\n";
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);

	$code.="	and	\$0x000000ff,$out\n";
	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	movzb	".&lo($tmp1).",$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";

	$code.="	mov	0($sbox,$tmp0,8),$tmp0\n";
	$code.="	mov	0($sbox,$tmp1,8),$tmp1\n";
	$code.="	mov	2($sbox,$tmp2,8),$tmp2\n";

	$code.="	and	\$0x0000ff00,$tmp0\n";
	$code.="	and	\$0x00ff0000,$tmp1\n";
	$code.="	and	\$0xff000000,$tmp2\n";

	$code.="	xor	$tmp0,$out\n";
	$code.="	mov	$t0,$s[1]\n"		if ($i==3);
	$code.="	xor	$tmp1,$out\n";
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	xor	$tmp2,$out\n";
	$code.="	mov	$t2,$s[3]\n"		if ($i==3);
	$code.="\n";
}

$code.=<<___;
.type	_x86_64_AES_encrypt,\@abi-omnipotent
.align	16
_x86_64_AES_encrypt:
	xor	0($key),$s0			# xor with key
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3

	mov	240($key),$rnds			# load key->rounds
	sub	\$1,$rnds
	jmp	.Lenc_loop
.align	16
.Lenc_loop:
___
	if ($verticalspin) { &encvert(); }
	else {	&encstep(0,$s0,$s1,$s2,$s3);
		&encstep(1,$s1,$s2,$s3,$s0);
		&encstep(2,$s2,$s3,$s0,$s1);
		&encstep(3,$s3,$s0,$s1,$s2);
	}
$code.=<<___;
	sub	\$1,$rnds
	jnz	.Lenc_loop
___
	if ($verticalspin) { &enclastvert(); }
	else {	&enclast(0,$s0,$s1,$s2,$s3);
		&enclast(1,$s1,$s2,$s3,$s0);
		&enclast(2,$s2,$s3,$s0,$s1);
		&enclast(3,$s3,$s0,$s1,$s2);
		$code.=<<___;
		xor	16+0($key),$s0		# xor with key
		xor	16+4($key),$s1
		xor	16+8($key),$s2
		xor	16+12($key),$s3
___
	}
$code.=<<___;
	.byte	0xf3,0xc3			# rep ret
.size	_x86_64_AES_encrypt,.-_x86_64_AES_encrypt
___

# it's possible to implement this by shifting tN by 8, filling least
# significant byte with byte load and finally bswap-ing at the end,
# but such partial register load kills Core 2...
sub enccompactvert()
{ my ($t3,$t4,$t5)=("%r8d","%r9d","%r13d");

$code.=<<___;
	movzb	`&lo("$s0")`,$t0
	movzb	`&lo("$s1")`,$t1
	movzb	`&lo("$s2")`,$t2
	movzb	`&lo("$s3")`,$t3
	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	shr	\$16,$s2
	movzb	`&hi("$s3")`,$acc2
	movzb	($sbox,$t0,1),$t0
	movzb	($sbox,$t1,1),$t1
	movzb	($sbox,$t2,1),$t2
	movzb	($sbox,$t3,1),$t3

	movzb	($sbox,$acc0,1),$t4	#$t0
	movzb	`&hi("$s0")`,$acc0
	movzb	($sbox,$acc1,1),$t5	#$t1
	movzb	`&lo("$s2")`,$acc1
	movzb	($sbox,$acc2,1),$acc2	#$t2
	movzb	($sbox,$acc0,1),$acc0	#$t3

	shl	\$8,$t4
	shr	\$16,$s3
	shl	\$8,$t5
	xor	$t4,$t0
	shr	\$16,$s0
	movzb	`&lo("$s3")`,$t4
	shr	\$16,$s1
	xor	$t5,$t1
	shl	\$8,$acc2
	movzb	`&lo("$s0")`,$t5
	movzb	($sbox,$acc1,1),$acc1	#$t0
	xor	$acc2,$t2

	shl	\$8,$acc0
	movzb	`&lo("$s1")`,$acc2
	shl	\$16,$acc1
	xor	$acc0,$t3
	movzb	($sbox,$t4,1),$t4	#$t1
	movzb	`&hi("$s3")`,$acc0
	movzb	($sbox,$t5,1),$t5	#$t2
	xor	$acc1,$t0

	shr	\$8,$s2
	movzb	`&hi("$s0")`,$acc1
	shl	\$16,$t4
	shr	\$8,$s1
	shl	\$16,$t5
	xor	$t4,$t1
	movzb	($sbox,$acc2,1),$acc2	#$t3
	movzb	($sbox,$acc0,1),$acc0	#$t0
	movzb	($sbox,$acc1,1),$acc1	#$t1
	movzb	($sbox,$s2,1),$s3	#$t3
	movzb	($sbox,$s1,1),$s2	#$t2

	shl	\$16,$acc2
	xor	$t5,$t2
	shl	\$24,$acc0
	xor	$acc2,$t3
	shl	\$24,$acc1
	xor	$acc0,$t0
	shl	\$24,$s3
	xor	$acc1,$t1
	shl	\$24,$s2
	mov	$t0,$s0
	mov	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub enctransform_ref()
{ my $sn = shift;
  my ($acc,$r2,$tmp)=("%r8d","%r9d","%r13d");

$code.=<<___;
	mov	$sn,$acc
	and	\$0x80808080,$acc
	mov	$acc,$tmp
	shr	\$7,$tmp
	lea	($sn,$sn),$r2
	sub	$tmp,$acc
	and	\$0xfefefefe,$r2
	and	\$0x1b1b1b1b,$acc
	mov	$sn,$tmp
	xor	$acc,$r2

	xor	$r2,$sn
	rol	\$24,$sn
	xor	$r2,$sn
	ror	\$16,$tmp
	xor	$tmp,$sn
	ror	\$8,$tmp
	xor	$tmp,$sn
___
}

# unlike decrypt case it does not pay off to parallelize enctransform
sub enctransform()
{ my ($t3,$r20,$r21)=($acc2,"%r8d","%r9d");

$code.=<<___;
	mov	\$0x80808080,$t0
	mov	\$0x80808080,$t1
	and	$s0,$t0
	and	$s1,$t1
	mov	$t0,$acc0
	mov	$t1,$acc1
	shr	\$7,$t0
	lea	($s0,$s0),$r20
	shr	\$7,$t1
	lea	($s1,$s1),$r21
	sub	$t0,$acc0
	sub	$t1,$acc1
	and	\$0xfefefefe,$r20
	and	\$0xfefefefe,$r21
	and	\$0x1b1b1b1b,$acc0
	and	\$0x1b1b1b1b,$acc1
	mov	$s0,$t0
	mov	$s1,$t1
	xor	$acc0,$r20
	xor	$acc1,$r21

	xor	$r20,$s0
	xor	$r21,$s1
	 mov	\$0x80808080,$t2
	rol	\$24,$s0
	 mov	\$0x80808080,$t3
	rol	\$24,$s1
	 and	$s2,$t2
	 and	$s3,$t3
	xor	$r20,$s0
	xor	$r21,$s1
	 mov	$t2,$acc0
	ror	\$16,$t0
	 mov	$t3,$acc1
	ror	\$16,$t1
	 lea	($s2,$s2),$r20
	 shr	\$7,$t2
	xor	$t0,$s0
	 shr	\$7,$t3
	xor	$t1,$s1
	ror	\$8,$t0
	 lea	($s3,$s3),$r21
	ror	\$8,$t1
	 sub	$t2,$acc0
	 sub	$t3,$acc1
	xor	$t0,$s0
	xor	$t1,$s1

	and	\$0xfefefefe,$r20
	and	\$0xfefefefe,$r21
	and	\$0x1b1b1b1b,$acc0
	and	\$0x1b1b1b1b,$acc1
	mov	$s2,$t2
	mov	$s3,$t3
	xor	$acc0,$r20
	xor	$acc1,$r21

	ror	\$16,$t2
	xor	$r20,$s2
	ror	\$16,$t3
	xor	$r21,$s3
	rol	\$24,$s2
	mov	0($sbox),$acc0			# prefetch Te4
	rol	\$24,$s3
	xor	$r20,$s2
	mov	64($sbox),$acc1
	xor	$r21,$s3
	mov	128($sbox),$r20
	xor	$t2,$s2
	ror	\$8,$t2
	xor	$t3,$s3
	ror	\$8,$t3
	xor	$t2,$s2
	mov	192($sbox),$r21
	xor	$t3,$s3
___
}

$code.=<<___;
.type	_x86_64_AES_encrypt_compact,\@abi-omnipotent
.align	16
_x86_64_AES_encrypt_compact:
	lea	128($sbox),$inp			# size optimization
	mov	0-128($inp),$acc1		# prefetch Te4
	mov	32-128($inp),$acc2
	mov	64-128($inp),$t0
	mov	96-128($inp),$t1
	mov	128-128($inp),$acc1
	mov	160-128($inp),$acc2
	mov	192-128($inp),$t0
	mov	224-128($inp),$t1
	jmp	.Lenc_loop_compact
.align	16
.Lenc_loop_compact:
		xor	0($key),$s0		# xor with key
		xor	4($key),$s1
		xor	8($key),$s2
		xor	12($key),$s3
		lea	16($key),$key
___
		&enccompactvert();
$code.=<<___;
		cmp	16(%rsp),$key
		je	.Lenc_compact_done
___
		&enctransform();
$code.=<<___;
	jmp	.Lenc_loop_compact
.align	16
.Lenc_compact_done:
	xor	0($key),$s0
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3
	.byte	0xf3,0xc3			# rep ret
.size	_x86_64_AES_encrypt_compact,.-_x86_64_AES_encrypt_compact
___

# void GFp_aes_nohw_encrypt (const void *inp,void *out,const AES_KEY *key);
$code.=<<___;
.align	16
.globl	GFp_aes_nohw_encrypt
.type	GFp_aes_nohw_encrypt,\@function,3
.hidden	GFp_aes_nohw_encrypt
GFp_aes_nohw_encrypt:
.cfi_startproc
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15

	# allocate frame "above" key schedule
	lea	-63(%rdx),%rcx	# %rdx is key argument
	and	\$-64,%rsp
	sub	%rsp,%rcx
	neg	%rcx
	and	\$0x3c0,%rcx
	sub	%rcx,%rsp
	sub	\$32,%rsp

	mov	%rsi,16(%rsp)	# save out
	mov	%rax,24(%rsp)	# save original stack pointer
.cfi_cfa_expression	%rsp+24,deref,+8
.Lenc_prologue:

	mov	%rdx,$key
	mov	240($key),$rnds	# load rounds

	mov	0(%rdi),$s0	# load input vector
	mov	4(%rdi),$s1
	mov	8(%rdi),$s2
	mov	12(%rdi),$s3

	shl	\$4,$rnds
	lea	($key,$rnds),%rbp
	mov	$key,(%rsp)	# key schedule
	mov	%rbp,8(%rsp)	# end of key schedule

	# pick Te4 copy which can't "overlap" with stack frame or key schedule
	lea	.LAES_Te+2048(%rip),$sbox
	lea	768(%rsp),%rbp
	sub	$sbox,%rbp
	and	\$0x300,%rbp
	lea	($sbox,%rbp),$sbox

	call	_x86_64_AES_encrypt_compact

	mov	16(%rsp),$out	# restore out
	mov	24(%rsp),%rsi	# restore saved stack pointer
.cfi_def_cfa	%rsi,8
	mov	$s0,0($out)	# write output vector
	mov	$s1,4($out)
	mov	$s2,8($out)
	mov	$s3,12($out)

	mov	-48(%rsi),%r15
.cfi_restore	%r15
	mov	-40(%rsi),%r14
.cfi_restore	%r14
	mov	-32(%rsi),%r13
.cfi_restore	%r13
	mov	-24(%rsi),%r12
.cfi_restore	%r12
	mov	-16(%rsi),%rbp
.cfi_restore	%rbp
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lenc_epilogue:
	ret
.cfi_endproc
.size	GFp_aes_nohw_encrypt,.-GFp_aes_nohw_encrypt
___

#------------------------------------------------------------------#

sub enckey()
{
$code.=<<___;
	movz	%dl,%esi		# rk[i]>>0
	movzb	-128(%rbp,%rsi),%ebx
	movz	%dh,%esi		# rk[i]>>8
	shl	\$24,%ebx
	xor	%ebx,%eax

	movzb	-128(%rbp,%rsi),%ebx
	shr	\$16,%edx
	movz	%dl,%esi		# rk[i]>>16
	xor	%ebx,%eax

	movzb	-128(%rbp,%rsi),%ebx
	movz	%dh,%esi		# rk[i]>>24
	shl	\$8,%ebx
	xor	%ebx,%eax

	movzb	-128(%rbp,%rsi),%ebx
	shl	\$16,%ebx
	xor	%ebx,%eax

	xor	1024-128(%rbp,%rcx,4),%eax		# rcon
___
}

# int GFp_aes_nohw_set_encrypt_key(const unsigned char *userKey, const int bits,
#                                 AES_KEY *key)
$code.=<<___;
.align	16
.globl GFp_aes_nohw_set_encrypt_key
.type  GFp_aes_nohw_set_encrypt_key,\@function,3
GFp_aes_nohw_set_encrypt_key:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12			# redundant, but allows to share
.cfi_push	%r12
	push	%r13			# exception handler...
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	\$8,%rsp
.cfi_adjust_cfa_offset	8
.Lenc_key_prologue:

	call	_x86_64_AES_set_encrypt_key

	mov	40(%rsp),%rbp
.cfi_restore	%rbp
	mov	48(%rsp),%rbx
.cfi_restore	%rbx
	add	\$56,%rsp
.cfi_adjust_cfa_offset	-56
.Lenc_key_epilogue:
	ret
.cfi_endproc
.size GFp_aes_nohw_set_encrypt_key,.-GFp_aes_nohw_set_encrypt_key

.type	_x86_64_AES_set_encrypt_key,\@abi-omnipotent
.align	16
_x86_64_AES_set_encrypt_key:
	mov	%esi,%ecx			# %ecx=bits
	mov	%rdi,%rsi			# %rsi=userKey
	mov	%rdx,%rdi			# %rdi=key

	test	\$-1,%rsi
	jz	.Lbadpointer
	test	\$-1,%rdi
	jz	.Lbadpointer

	lea	.LAES_Te(%rip),%rbp
	lea	2048+128(%rbp),%rbp

	# prefetch Te4
	mov	0-128(%rbp),%eax
	mov	32-128(%rbp),%ebx
	mov	64-128(%rbp),%r8d
	mov	96-128(%rbp),%edx
	mov	128-128(%rbp),%eax
	mov	160-128(%rbp),%ebx
	mov	192-128(%rbp),%r8d
	mov	224-128(%rbp),%edx

	cmp	\$128,%ecx
	je	.L10rounds
	cmp	\$256,%ecx
	je	.L14rounds
	mov	\$-2,%rax			# invalid number of bits
	jmp	.Lexit

.L10rounds:
	mov	0(%rsi),%rax			# copy first 4 dwords
	mov	8(%rsi),%rdx
	mov	%rax,0(%rdi)
	mov	%rdx,8(%rdi)

	shr	\$32,%rdx
	xor	%ecx,%ecx
	jmp	.L10shortcut
.align	4
.L10loop:
		mov	0(%rdi),%eax			# rk[0]
		mov	12(%rdi),%edx			# rk[3]
.L10shortcut:
___
		&enckey	();
$code.=<<___;
		mov	%eax,16(%rdi)			# rk[4]
		xor	4(%rdi),%eax
		mov	%eax,20(%rdi)			# rk[5]
		xor	8(%rdi),%eax
		mov	%eax,24(%rdi)			# rk[6]
		xor	12(%rdi),%eax
		mov	%eax,28(%rdi)			# rk[7]
		add	\$1,%ecx
		lea	16(%rdi),%rdi
		cmp	\$10,%ecx
	jl	.L10loop

	movl	\$10,80(%rdi)			# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.L14rounds:		
	mov	0(%rsi),%rax			# copy first 8 dwords
	mov	8(%rsi),%rbx
	mov	16(%rsi),%rcx
	mov	24(%rsi),%rdx
	mov	%rax,0(%rdi)
	mov	%rbx,8(%rdi)
	mov	%rcx,16(%rdi)
	mov	%rdx,24(%rdi)

	shr	\$32,%rdx
	xor	%ecx,%ecx
	jmp	.L14shortcut
.align	4
.L14loop:
		mov	0(%rdi),%eax			# rk[0]
		mov	28(%rdi),%edx			# rk[4]
.L14shortcut:
___
		&enckey	();
$code.=<<___;
		mov	%eax,32(%rdi)			# rk[8]
		xor	4(%rdi),%eax
		mov	%eax,36(%rdi)			# rk[9]
		xor	8(%rdi),%eax
		mov	%eax,40(%rdi)			# rk[10]
		xor	12(%rdi),%eax
		mov	%eax,44(%rdi)			# rk[11]

		cmp	\$6,%ecx
		je	.L14break
		add	\$1,%ecx

		mov	%eax,%edx
		mov	16(%rdi),%eax			# rk[4]
		movz	%dl,%esi			# rk[11]>>0
		movzb	-128(%rbp,%rsi),%ebx
		movz	%dh,%esi			# rk[11]>>8
		xor	%ebx,%eax

		movzb	-128(%rbp,%rsi),%ebx
		shr	\$16,%edx
		shl	\$8,%ebx
		movz	%dl,%esi			# rk[11]>>16
		xor	%ebx,%eax

		movzb	-128(%rbp,%rsi),%ebx
		movz	%dh,%esi			# rk[11]>>24
		shl	\$16,%ebx
		xor	%ebx,%eax

		movzb	-128(%rbp,%rsi),%ebx
		shl	\$24,%ebx
		xor	%ebx,%eax

		mov	%eax,48(%rdi)			# rk[12]
		xor	20(%rdi),%eax
		mov	%eax,52(%rdi)			# rk[13]
		xor	24(%rdi),%eax
		mov	%eax,56(%rdi)			# rk[14]
		xor	28(%rdi),%eax
		mov	%eax,60(%rdi)			# rk[15]

		lea	32(%rdi),%rdi
	jmp	.L14loop
.L14break:
	movl	\$14,48(%rdi)		# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.Lbadpointer:
	mov	\$-1,%rax
.Lexit:
	.byte	0xf3,0xc3			# rep ret
.size	_x86_64_AES_set_encrypt_key,.-_x86_64_AES_set_encrypt_key
___

$code.=<<___;
.align	64
.LAES_Te:
___
	&_data_word(0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6);
	&_data_word(0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591);
	&_data_word(0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56);
	&_data_word(0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec);
	&_data_word(0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa);
	&_data_word(0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb);
	&_data_word(0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45);
	&_data_word(0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b);
	&_data_word(0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c);
	&_data_word(0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83);
	&_data_word(0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9);
	&_data_word(0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a);
	&_data_word(0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d);
	&_data_word(0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f);
	&_data_word(0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df);
	&_data_word(0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea);
	&_data_word(0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34);
	&_data_word(0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b);
	&_data_word(0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d);
	&_data_word(0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413);
	&_data_word(0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1);
	&_data_word(0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6);
	&_data_word(0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972);
	&_data_word(0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85);
	&_data_word(0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed);
	&_data_word(0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511);
	&_data_word(0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe);
	&_data_word(0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b);
	&_data_word(0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05);
	&_data_word(0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1);
	&_data_word(0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142);
	&_data_word(0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf);
	&_data_word(0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3);
	&_data_word(0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e);
	&_data_word(0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a);
	&_data_word(0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6);
	&_data_word(0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3);
	&_data_word(0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b);
	&_data_word(0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428);
	&_data_word(0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad);
	&_data_word(0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14);
	&_data_word(0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8);
	&_data_word(0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4);
	&_data_word(0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2);
	&_data_word(0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda);
	&_data_word(0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949);
	&_data_word(0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf);
	&_data_word(0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810);
	&_data_word(0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c);
	&_data_word(0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697);
	&_data_word(0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e);
	&_data_word(0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f);
	&_data_word(0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc);
	&_data_word(0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c);
	&_data_word(0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969);
	&_data_word(0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27);
	&_data_word(0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122);
	&_data_word(0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433);
	&_data_word(0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9);
	&_data_word(0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5);
	&_data_word(0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a);
	&_data_word(0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0);
	&_data_word(0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e);
	&_data_word(0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c);

#Te4	# four copies of Te4 to choose from to avoid L1 aliasing
	&data_byte(0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5);
	&data_byte(0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76);
	&data_byte(0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0);
	&data_byte(0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0);
	&data_byte(0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc);
	&data_byte(0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15);
	&data_byte(0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a);
	&data_byte(0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75);
	&data_byte(0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0);
	&data_byte(0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84);
	&data_byte(0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b);
	&data_byte(0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf);
	&data_byte(0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85);
	&data_byte(0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8);
	&data_byte(0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5);
	&data_byte(0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2);
	&data_byte(0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17);
	&data_byte(0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73);
	&data_byte(0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88);
	&data_byte(0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb);
	&data_byte(0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c);
	&data_byte(0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79);
	&data_byte(0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9);
	&data_byte(0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08);
	&data_byte(0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6);
	&data_byte(0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a);
	&data_byte(0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e);
	&data_byte(0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e);
	&data_byte(0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94);
	&data_byte(0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf);
	&data_byte(0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68);
	&data_byte(0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);

	&data_byte(0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5);
	&data_byte(0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76);
	&data_byte(0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0);
	&data_byte(0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0);
	&data_byte(0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc);
	&data_byte(0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15);
	&data_byte(0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a);
	&data_byte(0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75);
	&data_byte(0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0);
	&data_byte(0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84);
	&data_byte(0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b);
	&data_byte(0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf);
	&data_byte(0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85);
	&data_byte(0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8);
	&data_byte(0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5);
	&data_byte(0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2);
	&data_byte(0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17);
	&data_byte(0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73);
	&data_byte(0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88);
	&data_byte(0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb);
	&data_byte(0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c);
	&data_byte(0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79);
	&data_byte(0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9);
	&data_byte(0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08);
	&data_byte(0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6);
	&data_byte(0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a);
	&data_byte(0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e);
	&data_byte(0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e);
	&data_byte(0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94);
	&data_byte(0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf);
	&data_byte(0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68);
	&data_byte(0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);

	&data_byte(0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5);
	&data_byte(0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76);
	&data_byte(0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0);
	&data_byte(0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0);
	&data_byte(0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc);
	&data_byte(0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15);
	&data_byte(0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a);
	&data_byte(0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75);
	&data_byte(0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0);
	&data_byte(0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84);
	&data_byte(0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b);
	&data_byte(0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf);
	&data_byte(0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85);
	&data_byte(0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8);
	&data_byte(0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5);
	&data_byte(0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2);
	&data_byte(0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17);
	&data_byte(0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73);
	&data_byte(0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88);
	&data_byte(0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb);
	&data_byte(0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c);
	&data_byte(0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79);
	&data_byte(0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9);
	&data_byte(0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08);
	&data_byte(0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6);
	&data_byte(0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a);
	&data_byte(0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e);
	&data_byte(0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e);
	&data_byte(0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94);
	&data_byte(0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf);
	&data_byte(0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68);
	&data_byte(0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);

	&data_byte(0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5);
	&data_byte(0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76);
	&data_byte(0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0);
	&data_byte(0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0);
	&data_byte(0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc);
	&data_byte(0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15);
	&data_byte(0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a);
	&data_byte(0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75);
	&data_byte(0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0);
	&data_byte(0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84);
	&data_byte(0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b);
	&data_byte(0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf);
	&data_byte(0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85);
	&data_byte(0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8);
	&data_byte(0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5);
	&data_byte(0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2);
	&data_byte(0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17);
	&data_byte(0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73);
	&data_byte(0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88);
	&data_byte(0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb);
	&data_byte(0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c);
	&data_byte(0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79);
	&data_byte(0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9);
	&data_byte(0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08);
	&data_byte(0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6);
	&data_byte(0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a);
	&data_byte(0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e);
	&data_byte(0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e);
	&data_byte(0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94);
	&data_byte(0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf);
	&data_byte(0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68);
	&data_byte(0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);
#rcon:
$code.=<<___;
	.long	0x00000001, 0x00000002, 0x00000004, 0x00000008
	.long	0x00000010, 0x00000020, 0x00000040, 0x00000080
	.long	0x0000001b, 0x00000036, 0x80808080, 0x80808080
	.long	0xfefefefe, 0xfefefefe, 0x1b1b1b1b, 0x1b1b1b1b
___

$code.=<<___;
.asciz  "AES for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
.align	64
___

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	block_se_handler,\@abi-omnipotent
.align	16
block_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# prologue label
	cmp	%r10,%rbx		# context->Rip<prologue label
	jb	.Lin_block_prologue

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lin_block_prologue

	mov	24(%rax),%rax		# pull saved real stack pointer

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

.Lin_block_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	jmp	.Lcommon_seh_exit
.size	block_se_handler,.-block_se_handler

.type	key_se_handler,\@abi-omnipotent
.align	16
key_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# prologue label
	cmp	%r10,%rbx		# context->Rip<prologue label
	jb	.Lin_key_prologue

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lin_key_prologue

	lea	56(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

.Lin_key_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

.Lcommon_seh_exit:
	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$`1232/8`,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	key_se_handler,.-key_se_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_GFp_aes_nohw_encrypt
	.rva	.LSEH_end_GFp_aes_nohw_encrypt
	.rva	.LSEH_info_GFp_aes_nohw_encrypt

	.rva	.LSEH_begin_GFp_aes_nohw_set_encrypt_key
	.rva	.LSEH_end_GFp_aes_nohw_set_encrypt_key
	.rva	.LSEH_info_GFp_aes_nohw_set_encrypt_key

.section	.xdata
.align	8
.LSEH_info_GFp_aes_nohw_encrypt:
	.byte	9,0,0,0
	.rva	block_se_handler
	.rva	.Lenc_prologue,.Lenc_epilogue	# HandlerData[]
.LSEH_info_GFp_aes_nohw_set_encrypt_key:
	.byte	9,0,0,0
	.rva	key_se_handler
	.rva	.Lenc_key_prologue,.Lenc_key_epilogue	# HandlerData[]
___
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
