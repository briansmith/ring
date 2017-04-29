#!/usr/bin/env perl
#
# Copyright 2017 Peter Reid.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$code.=<<___;
.globl	GFp_cpuid
.type	GFp_cpuid,\@function,5
.align	32
GFp_cpuid:
	push %rbx
	movq %rsi,%rax
	xor %rcx,%rcx
	cpuid
	movl %eax,0x00(%rdi)
	movl %ebx,0x04(%rdi)
	movl %ecx,0x08(%rdi)
	movl %edx,0x0c(%rdi)
	pop %rbx
	ret
___

$code.=<<___;
.globl	GFp_xcr0_low
.type	GFp_xcr0_low,\@function,5
.align	32
GFp_xcr0_low:
	xor %rcx,%rcx
	xgetbv
	ret
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
