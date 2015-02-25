#!/usr/bin/env perl

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

($arg1,$arg2,$arg3,$arg4)=$win64?("%rcx","%rdx","%r8", "%r9") :	# Win64 order
				 ("%rdi","%rsi","%rdx","%rcx");	# Unix order

print<<___;
.text

.globl	OPENSSL_ia32_cpuid
.type	OPENSSL_ia32_cpuid,\@function,1
.align	16
OPENSSL_ia32_cpuid:
	# On Windows, $arg1 is rcx, but that will be clobbered. So make Windows
	# use the same register as Unix.
	mov	$arg1,%rdi
	mov	%rbx,%r8		# save %rbx

	xor	%eax,%eax
	mov	%eax,8(%rdi)		# clear 3rd word
	cpuid
	mov	%eax,%r11d		# max value for standard query level

	xor	%eax,%eax
	cmp	\$0x756e6547,%ebx	# "Genu"
	setne	%al
	mov	%eax,%r9d
	cmp	\$0x49656e69,%edx	# "ineI"
	setne	%al
	or	%eax,%r9d
	cmp	\$0x6c65746e,%ecx	# "ntel"
	setne	%al
	or	%eax,%r9d		# 0 indicates Intel CPU
	jz	.Lintel

	cmp	\$0x68747541,%ebx	# "Auth"
	setne	%al
	mov	%eax,%r10d
	cmp	\$0x69746E65,%edx	# "enti"
	setne	%al
	or	%eax,%r10d
	cmp	\$0x444D4163,%ecx	# "cAMD"
	setne	%al
	or	%eax,%r10d		# 0 indicates AMD CPU
	jnz	.Lintel

	# AMD specific
	# See http://developer.amd.com/wordpress/media/2012/10/254811.pdf (1)

	mov	\$0x80000000,%eax
	cpuid
	# Returns "The largest CPUID extended function input value supported by
	# the processor implementation." in EAX.
	cmp	\$0x80000001,%eax
	jb	.Lintel
	mov	%eax,%r10d
	mov	\$0x80000001,%eax
	cpuid
	# Returns feature bits in ECX. See page 20 of [1].
	# TODO(fork): I think this should be a MOV.
	or	%ecx,%r9d
	and	\$0x00000801,%r9d	# isolate AMD XOP bit, 1<<11

	cmp	\$0x80000008,%r10d
	jb	.Lintel

	mov	\$0x80000008,%eax
	cpuid
	# Returns APIC ID and number of cores in ECX. See page 27 of [1].
	movzb	%cl,%r10		# number of cores - 1
	inc	%r10			# number of cores

	mov	\$1,%eax
	cpuid
	# See page 13 of [1].
	bt	\$28,%edx		# test hyper-threading bit
	jnc	.Lgeneric
	shr	\$16,%ebx		# number of logical processors
	cmp	%r10b,%bl
	ja	.Lgeneric
	and	\$0xefffffff,%edx	# Clear hyper-threading bit.
	jmp	.Lgeneric

.Lintel:
	cmp	\$4,%r11d
	mov	\$-1,%r10d
	jb	.Lnocacheinfo

	mov	\$4,%eax
	mov	\$0,%ecx		# query L1D
	cpuid
	mov	%eax,%r10d
	shr	\$14,%r10d
	and	\$0xfff,%r10d		# number of cores -1 per L1D

	cmp	\$7,%r11d
	jb	.Lnocacheinfo

	mov	\$7,%eax
	xor	%ecx,%ecx
	cpuid
	mov	%ebx,8(%rdi)

.Lnocacheinfo:
	mov	\$1,%eax
	cpuid
	# Gets feature information. See table 3-21 in the Intel manual.
	and	\$0xbfefffff,%edx	# force reserved bits to 0
	cmp	\$0,%r9d
	jne	.Lnotintel
	or	\$0x40000000,%edx	# set reserved bit#30 on Intel CPUs
.Lnotintel:
	bt	\$28,%edx		# test hyper-threading bit
	jnc	.Lgeneric
	and	\$0xefffffff,%edx	# ~(1<<28) - clear hyper-threading.
	cmp	\$0,%r10d
	je	.Lgeneric

	or	\$0x10000000,%edx	# 1<<28
	shr	\$16,%ebx
	cmp	\$1,%bl			# see if cache is shared
	ja	.Lgeneric
	and	\$0xefffffff,%edx	# ~(1<<28)
.Lgeneric:
	and	\$0x00000800,%r9d	# isolate AMD XOP flag
	and	\$0xfffff7ff,%ecx
	or	%ecx,%r9d		# merge AMD XOP flag

	mov	%edx,%r10d		# %r9d:%r10d is copy of %ecx:%edx
	bt	\$27,%r9d		# check OSXSAVE bit
	jnc	.Lclear_avx
	xor	%ecx,%ecx		# XCR0
	.byte	0x0f,0x01,0xd0		# xgetbv
	and	\$6,%eax		# isolate XMM and YMM state support
	cmp	\$6,%eax
	je	.Ldone
.Lclear_avx:
	mov	\$0xefffe7ff,%eax	# ~(1<<28|1<<12|1<<11)
	and	%eax,%r9d		# clear AVX, FMA and AMD XOP bits
	andl	\$0xffffffdf,8(%rdi)	# cleax AVX2, ~(1<<5)
.Ldone:
	movl	%r9d,4(%rdi)
	movl	%r10d,0(%rdi)
	mov	%r8,%rbx		# restore %rbx
	ret
.size	OPENSSL_ia32_cpuid,.-OPENSSL_ia32_cpuid

___

close STDOUT;	# flush
