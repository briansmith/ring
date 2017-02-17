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


$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../perlasm");
require "x86asm.pl";

$output = pop;
open OUT,">$output";
*STDOUT=*OUT;

&asm_init($ARGV[0],"cpu-x86.pl",$x86only = $ARGV[$#ARGV] eq "386");

&function_begin("GFp_cpuid");
	&mov("eax", &wparam(1));
	&mov("esi",&wparam(0));
	&xor("ecx", "ecx");
	&cpuid();
	&mov(&DWP(0, "esi"), "eax");
	&mov(&DWP(4, "esi"), "ebx");
	&mov(&DWP(8, "esi"), "ecx");
	&mov(&DWP(12, "esi"), "edx");
&function_end("GFp_cpuid");

&function_begin("GFp_xcr0_low");
	&xor("ecx", "ecx");
	&xgetbv();
&function_end("GFp_xcr0_low");

&asm_finish();

close STDOUT;
