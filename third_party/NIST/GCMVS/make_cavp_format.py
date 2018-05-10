cavp_encryption = [
    'gcmEncryptExtIV128.rsp',
    'gcmEncryptExtIV256.rsp',
]

cavp_decryption = [
    'gcmDecrypt128.rsp',
    'gcmDecrypt256.rsp',
]

keyword_replacements = {
    'Key' : 'KEY',
    'IV' : 'NONCE',
    'PT' : 'IN',
    'AAD' : 'AD',
    'Tag' : 'TAG',
    'FAIL' : 'FAILS = FAILS_TO_DECRYPT',
}

lines = []

for file in cavp_encryption:
    with open('third_party/NIST/CAVPGCM/' + file) as infile:
        for line in infile:
            for src, target in keyword_replacements.items():
                line = line.replace(src, target)
            if line.endswith("= \n"):
                line = line.replace(' = ', ' = ""')

            # A TAG of length 128-bits will be of length 32 in hex
            # 'TAG = ' is 6 in length
            # 'NONCE = ' is 8 in length
            # The remaining 1 in length is a newline
            # len(TAG) = 39, len(NONCE) = 33

            # Check TAG length
            if not line.startswith("TAG =") or (len(line) == 39):
                if not line.startswith("Count = "):
                    if not line.startswith("["):
                        lines.append(line)
                    if line.startswith("TAG =") and (len(lines[-5]) != 33):
                        # Check if the last NONCE, in pos -5, was of valid length
                        lines.append('FAILS = WRONG_NONCE_LENGTH\n')
            else:
                # If the TAG has invalid size, we trim the test case
                # elements which includes KEY, NONCE, etc
                for x in range(1,7):
                    lines.pop()

    with open('third_party/NIST/CAVPGCM/' + file + '_ring.rsp', 'w') as outfile:
        for line in lines:
            outfile.write(line)

    # Empty list
    lines[:] = []

for file in cavp_decryption:
    with open('third_party/NIST/CAVPGCM/' + file) as infile:
        for line in infile:
            for src, target in keyword_replacements.items():
                line = line.replace(src, target)
            if line.endswith("= \n"):
                line = line.replace(' = ', ' = ""')

            # A TAG of length 128-bits will be of length 32 in hex
            # 'TAG = ' is 6 in length
            # 'NONCE = ' is 8 in length
            # The remaining 1 in length is a newline
            # len(TAG) = 39, len(NONCE) = 33
            if not line.startswith("Count = "):
                if not line.startswith("["):
                    if line.startswith("FAILS = FAILS_TO_DECRYPT"):
                        # Check TAG length
                        if (len(lines[-1]) != 39):
                            # If not valid, remove whole test case
                            for x in range(1,7):
                                lines.pop()
                            continue
                        # Check NONCE length
                        if len(lines[-4]) != 33:
                            # *ring* does not accept invalid NONCE's so the
                            # FAILS_TO_DECRYPT can't be run at all, which is why
                            # we replace this with WRONG_NONCE_LENGTH
                            line = line.replace('FAILS = FAILS_TO_DECRYPT',
                                                'FAILS = WRONG_NONCE_LENGTH')

                        # Add the IN paramter, since this is not an optional
                        # argument for *ring*
                        lines.append('IN = ""\n')

                    if line.startswith("IN ="):
                        # Check TAG length
                        if (len(lines[-1]) != 39):
                            # If not valid, remove whole test case
                            for x in range(1,7):
                                lines.pop()
                            continue
                        # Check NONCE length
                        if (len(lines[-4]) != 33):
                            # If NONCE is not valid len
                            lines.append('FAILS = WRONG_NONCE_LENGTH\n')

                    lines.append(line)

    with open('third_party/NIST/CAVPGCM/' + file + '_ring.rsp', 'w') as outfile:
        for line in lines:
            outfile.write(line)

    # Empty list
    lines[:] = []
