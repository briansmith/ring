#!/usr/bin/env python2
#
# Copyright 2016 Dirkjan Ochtman.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''
Script to generate *ring* test file for RSA PKCS1 v1.5 signing test vectors
from the NIST FIPS 186-4 test vectors. Takes as single argument on the
command-line the path to the test vector file (tested with SigGen15_186-3.txt).

Requires the cryptography library from pyca.
'''

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sys, copy

def parse(fn):
    '''Parse input test vector file, leaving out comments and empty lines, and
    returns a list of self-contained test cases. Depends on the S key (for
    Signature) being the last value in each test case.'''
    cases = []
    with open(fn) as f:
        cur = {}
        for ln in f:
            if not ln.strip():
                continue
            if ln[0] in {'#', '['}:
                continue
            name, val = ln.split('=', 1)
            cur[name.strip()] = val.strip()
            if name.strip() == 'S':
                cases.append(cur)
                cur = copy.copy(cur)
    return cases

def main(fn):
    for case in parse(fn):

        if case['SHAAlg'] == 'SHA224':
            # SHA224 not supported in *ring*.
            continue

        # Read private key components.
        n = int(case['n'], 16)
        e = int(case['e'], 16)
        d = int(case['d'], 16)

        # Recover the prime factors and CRT numbers.
        p, q = rsa.rsa_recover_prime_factors(n, e, d)
        # cryptography returns p, q with p < q by default. *ring* requires
        # p > q, so swap them here.
        p, q = max(p, q), min(p, q)
        dmp1 = rsa.rsa_crt_dmp1(d, p)
        dmq1 = rsa.rsa_crt_dmq1(d, q)
        iqmp = rsa.rsa_crt_iqmp(p, q)

        # Create a private key instance.
        pub = rsa.RSAPublicNumbers(e, n)
        priv = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
        key = priv.private_key(default_backend())

        # Recalculate and compare the signature to validate our processing.
        msg = case['Msg'].decode('hex')
        sig = key.sign(msg, padding.PKCS1v15(),
                       getattr(hashes, case['SHAAlg'])())
        hex_sig = ''.join('{:02x}'.format(ord(c)) for c in sig)
        assert hex_sig == case['S']

        # Serialize the private key in DER format.
        der = key.private_bytes(serialization.Encoding.DER,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
        hex_der = ''.join('{:02x}'.format(ord(c)) for c in der)

        # Print the test case data in the format used by *ring* test files.
        print 'Digest = %s' % case['SHAAlg']
        print 'Key = %s' % hex_der
        print 'Msg = %s' % case['Msg']
        print 'Sig = %s' % case['S']
        print 'Result = Pass'
        print ''

if __name__ == '__main__':
    main(sys.argv[1])
