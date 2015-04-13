#!/usr/bin/env perl

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

print<<___;
.text

.globl	CRYPTO_rdrand
.type	CRYPTO_rdrand,\@function,1
.align	16
CRYPTO_rdrand:
	.byte 0x48, 0x0f, 0xc7, 0xf0
	retq
___

close STDOUT;	# flush
