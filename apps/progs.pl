#! /usr/bin/env perl
# Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Generate progs.h file by looking for command mains in list of C files
# passed on the command line.

use strict;
use warnings;
use configdata qw/@disablables/;

my %commands = ();
my $cmdre = qr/^\s*int\s+([a-z_][a-z0-9_]*)_main\(\s*int\s+argc\s*,/;

foreach my $filename (@ARGV) {
	open F, $filename or die "Coudn't open $_: $!\n";
	foreach (grep /$cmdre/, <F>) {
		my @foo = /$cmdre/;
		$commands{$1} = 1;
	}
	close F;
}

@ARGV = sort keys %commands;

print <<'EOF';
/*
 * WARNING: do not edit!
 * Generated by apps/progs.pl
 *
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

typedef enum FUNC_TYPE {
    FT_none, FT_general, FT_md, FT_cipher, FT_pkey,
    FT_md_alg, FT_cipher_alg
} FUNC_TYPE;

typedef struct function_st {
    FUNC_TYPE type;
    const char *name;
    int (*func)(int argc, char *argv[]);
    const OPTIONS *help;
} FUNCTION;

DEFINE_LHASH_OF(FUNCTION);

EOF

foreach (@ARGV) {
	printf "extern int %s_main(int argc, char *argv[]);\n", $_;
}

print "\n";

foreach (@ARGV) {
	printf "extern const OPTIONS %s_options[];\n", $_;
}

print "\n#ifdef INCLUDE_FUNCTION_TABLE\n";
print "static FUNCTION functions[] = {\n";
my %cmd_disabler = (
    ciphers  => "sock",
    genrsa   => "rsa",
    rsautl   => "rsa",
    gendsa   => "dsa",
    dsaparam => "dsa",
    gendh    => "dh",
    dhparam  => "dh",
    ecparam  => "ec",
    pkcs12   => "des",
    );
foreach my $cmd (@ARGV) {
	my $str="    {FT_general, \"$cmd\", ${cmd}_main, ${cmd}_options},\n";
	if ($cmd =~ /^s_/) {
		print "#ifndef OPENSSL_NO_SOCK\n${str}#endif\n";
	} elsif (grep { $cmd eq $_ } @disablables) {
		print "#ifndef OPENSSL_NO_".uc($cmd)."\n${str}#endif\n";
	} elsif (my $disabler = $cmd_disabler{$cmd}) {
		print "#ifndef OPENSSL_NO_".uc($disabler)."\n${str}#endif\n";
	} else {
		print $str;
	}
}

my %md_disabler = (
    blake2b512 => "blake2",
    blake2s256 => "blake2",
    );
foreach my $cmd (
	"md2", "md4", "md5",
	"gost",
	"sha1", "sha224", "sha256", "sha384", "sha512",
	"mdc2", "rmd160", "blake2b512", "blake2s256"
) {
        my $str = "    {FT_md, \"".$cmd."\", dgst_main},\n";
        if (grep { $cmd eq $_ } @disablables) {
                print "#ifndef OPENSSL_NO_".uc($cmd)."\n${str}#endif\n";
        } elsif (my $disabler = $md_disabler{$cmd}) {
                print "#ifndef OPENSSL_NO_".uc($disabler)."\n${str}#endif\n";
        } else {
                print $str;
        }
}

my %cipher_disabler = (
    des3  => "des",
    desx  => "des",
    cast5 => "cast",
    );
foreach my $cmd (
	"aes-128-cbc", "aes-128-ecb",
	"aes-192-cbc", "aes-192-ecb",
	"aes-256-cbc", "aes-256-ecb",
	"camellia-128-cbc", "camellia-128-ecb",
	"camellia-192-cbc", "camellia-192-ecb",
	"camellia-256-cbc", "camellia-256-ecb",
	"speck-256-cbc",
	"base64", "zlib",
	"des", "des3", "desx", "idea", "seed", "rc4", "rc4-40",
	"rc2", "bf", "cast", "rc5",
	"des-ecb", "des-ede",    "des-ede3",
	"des-cbc", "des-ede-cbc","des-ede3-cbc",
	"des-cfb", "des-ede-cfb","des-ede3-cfb",
	"des-ofb", "des-ede-ofb","des-ede3-ofb",
	"idea-cbc","idea-ecb",    "idea-cfb", "idea-ofb",
	"seed-cbc","seed-ecb",    "seed-cfb", "seed-ofb",
	"rc2-cbc", "rc2-ecb", "rc2-cfb","rc2-ofb", "rc2-64-cbc", "rc2-40-cbc",
	"bf-cbc",  "bf-ecb",     "bf-cfb",   "bf-ofb",
	"cast5-cbc","cast5-ecb", "cast5-cfb","cast5-ofb",
	"cast-cbc", "rc5-cbc",   "rc5-ecb",  "rc5-cfb",  "rc5-ofb"
) {
	my $str="    {FT_cipher, \"$cmd\", enc_main, enc_options},\n";
	(my $algo= $cmd) =~ s/-.*//g;
        if ($cmd eq "zlib") {
                print "#ifdef ZLIB\n${str}#endif\n";
        } elsif (grep { $algo eq $_ } @disablables) {
                print "#ifndef OPENSSL_NO_".uc($algo)."\n${str}#endif\n";
        } elsif (my $disabler = $cipher_disabler{$algo}) {
                print "#ifndef OPENSSL_NO_".uc($disabler)."\n${str}#endif\n";
	} else {
		print $str;
	}
}

print "    { 0, NULL, NULL}\n};\n";
print "#endif\n";
