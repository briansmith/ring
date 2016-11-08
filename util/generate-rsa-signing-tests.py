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

DIGEST_OUTPUT_LENGTHS = {
    'SHA1': 80,
    'SHA224': 112,
    'SHA256': 128,
    'SHA384': 192,
    'SHA512': 256
}

# Prints reasons for skipping tests
DEBUG = False

def debug(str, flag):
    if flag:
        sys.stderr.write(str + "\n")
        sys.stderr.flush()

def parse(fn, last_field):
    '''Parse input test vector file, leaving out comments and empty lines, and
    returns a list of self-contained test cases. Depends on the last_field
    being the last value in each test case.'''
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
            if name.strip() == last_field:
                cases.append(cur)
                cur = copy.copy(cur)
    return cases

def print_sign_test(case, n, e, d, padding_alg):
    # Can only support moduli which are a whole number of bytes
    if n.bit_length() % 8 != 0:
        debug("Skipping due to modulus (not a whole number of bytes).", DEBUG)
        return

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

    msg = case['Msg'].decode('hex')

    # Recalculate and compare the signature to validate our processing.
    if padding_alg == 'PKCS':
        sig = key.sign(msg, padding.PKCS1v15(),
                       getattr(hashes, case['SHAAlg'])())
        hex_sig = ''.join('{:02x}'.format(ord(c)) for c in sig)
        assert hex_sig == case['S']
    elif padding_alg != "PSS":
        # PSS is randomised, can't recompute this way
        print "Invalid padding algorithm"
        quit()

    # Serialize the private key in DER format.
    der = key.private_bytes(serialization.Encoding.DER,
                            serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    hex_der = ''.join('{:02x}'.format(ord(c)) for c in der)

    # Print the test case data in the format used by *ring* test files.
    print 'Digest = %s' % case['SHAAlg']
    print 'Key = %s' % hex_der
    print 'Msg = %s' % case['Msg']
    print 'Salt = %s' % case['SaltVal']
    print 'Sig = %s' % case['S']
    print 'Result = P'
    print ''

def print_verify_test(case, n, e):
    # Create a private key instance.
    pub = rsa.RSAPublicNumbers(e, n)
    key = pub.public_key(default_backend())

    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.PKCS1)
    hex_der = ''.join('{:02x}'.format(ord(c)) for c in der)

    # Print the test case data in the format used by *ring* test files.
    print 'Digest = %s' % case['SHAAlg']
    print 'Key = %s' % hex_der
    print 'Msg = %s' % case['Msg']
    print 'Sig = %s' % case['S']
    print 'Result = %s' % case['Result']
    print ''


def main(fn, test_type, padding_alg):
    # File header
    print "# NIST RSA PSS Test Vectors for FIPS 186-4 from %s in\n" % fn + \
    "# http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3rsatestvectors.zip\n" + \
    "# accessible from" + \
    "# http://csrc.nist.gov/groups/STM/cavp/digital-signatures.html#test-vectors.\n" + \
    "# Generated with the help of the util/generate-rsa-signing-tests.py script.\n" + \
    "#\n" + \
    "# Digest = SHAAlg.\n" + \
    "# Key is a DER-formatted PKCS1-encoded RSA key.\n" + \
    "# Sig = S.\n\n"

    num_cases = 0

    # Each test type has a different field as the last entry per case
    # For verify tests,PKCS "Result" is always the last field.
    # Otherwise, for signing tests, it is dependent on the padding used.
    if test_type == "verify":
        last_field = "Result"
    elif padding_alg == "PSS":
        last_field = "SaltVal"
    else:
        last_field = "S"

    for case in parse(fn, last_field):
        if case['SHAAlg'] == 'SHA224':
            # SHA224 not supported in *ring*.
            debug("Skipping due to use of SHA224", DEBUG)
            continue

        if case['SHAAlg'] == 'SHA1' and padding_alg == 'PSS':
            # SHA1 with PSS not supported in *ring.
            debug("Skipping due to use of SHA1 and PSS.", DEBUG)
            continue

        # We only support PSS where the salt length is equal to the output
        # length of the hash algorithm
        if padding_alg == "PSS":
            if len(case['SaltVal']) * 2 != DIGEST_OUTPUT_LENGTHS[case['SHAAlg']]:
                debug("Skipping due to incorrect salt length.", DEBUG)
                continue

        # Read private key components.
        n = int(case['n'], 16)
        e = int(case['e'], 16)
        d = int(case['d'], 16)

        if n.bit_length() < 2048:
            debug("Skipping due to modulus length (too small).", DEBUG)
            continue

        if n.bit_length() > 4096:
            debug("Skipping due to modulus length (too large).", DEBUG)
            continue

        if test_type == 'sign':
            print_sign_test(case, n, e, d, padding_alg)
        else:
            print_verify_test(case, n, e)

        num_cases += 1

    debug("%d test cases output." % num_cases, True)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage:\n" + \
        "\tpython generate-rsa-signing-tests.py" + \
        "<filename>"
    else:
        fn = sys.argv[1]
        if 'PSS' in fn:
            pad_alg = 'PSS'
        elif '15' in fn:
            pad_alg = 'PKCS'
        else:
            print "Could not determine padding algorithm,"
            quit()

        if 'Gen' in fn:
            test_type = 'sign'
        elif 'Ver' in fn:
            test_type = 'verify'
        else:
            print "Could not determine test type."
            quit()

        main(sys.argv[1], test_type, pad_alg)
