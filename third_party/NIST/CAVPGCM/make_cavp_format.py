files_en = [
    'gcmEncryptExtIV128.rsp',
    'gcmEncryptExtIV256.rsp',
]

replacements_en = {
    'Key' : 'KEY',
    'IV' : 'NONCE',
    'PT' : 'IN',
    'AAD' : 'AD',
    'Tag' : 'TAG',
}

lines = []
lines_de = []

for file in files_en:
    with open('third_party/NIST/CAVPGCM/' + file) as infile:
        for line in infile:
            for src, target in replacements_en.items():
                line = line.replace(src, target)
            if line.endswith("= \n"):
                line = line.replace(' = ', ' = ""')
            # A TAG of length 128-bits will be of length 32 in hex
            # 'TAG = ' gives 6 in length
            # 'NONCE = ' gives 8 in length
            # The remaining 1 in lenght is a newline
            # TAG = 39, NONCE = 33
            if not line.startswith("TAG =") or (line.startswith("TAG =") and (len(line) == 39)):
                if not line.startswith("Count = "):
                    if not line.startswith("["):
                        lines.append(line)
                    if line.startswith("TAG =") and (len(lines[-5]) != 33):
                        # Check if the last NONCE, in pos -5, was of valid length
                        lines.append('FAILS = WRONG_NONCE_LENGTH\n')
            else:
                # If the TAG has invalid size, we trim the previous test case
                # elements which includes KEY, NONCE, etc
                for x in range(1,7):
                    lines.pop()

    with open('third_party/NIST/CAVPGCM/' + file + '_ring.rsp', 'w') as outfile:
        for line in lines:
            outfile.write(line)

    # Empty list
    lines[:] = []


files_de = [
    'gcmDecrypt128.rsp',
    'gcmDecrypt256.rsp',
]

replacements_de = {
    'Key' : 'KEY',
    'IV' : 'NONCE',
    'PT' : 'IN',
    'AAD' : 'AD',
    'Tag' : 'TAG',
    'FAIL' : 'FAILS = FAILS_TO_DECRYPT',
}


for file in files_de:
    with open('third_party/NIST/CAVPGCM/' + file) as infile:
        for line in infile:
            for src, target in replacements_de.items():
                line = line.replace(src, target)
            if line.endswith("= \n"):
                line = line.replace(' = ', ' = ""')
            # A TAG of length 128-bits will be of length 32 in hex
            # 'TAG = ' gives 6 in length
            # 'NONCE = ' gives 8 in length
            # The remaining 1 in lenght is a newline
            # TAG = 39, NONCE = 33

            # If tag is 39 in length proceed
            if not line.startswith("Count = "):
                # 7a0c8b2ce3881518a9fd148a
                # bb8f8fd33bb70610de13df35
                if not line.startswith("["):
                    if line.startswith("FAILS = FAILS_TO_DECRYPT"):
                        # Append IN, ring needs this paramter
                        #lines_de.append('IN = ""\n')
                        # -5 because we added the IN element
                        if (len(lines_de[-1]) != 39):
                            # If TAG is not valid len
                            for x in range(1,7):
                                lines_de.pop()
                            continue

                        if len(lines_de[-4]) != 33:
                            line = line.replace('FAILS = FAILS_TO_DECRYPT', 'FAILS = WRONG_NONCE_LENGTH')

                        lines_de.append('IN = ""\n')

                    if line.startswith("IN ="):
                        if (len(lines_de[-1]) != 39):
                            # If TAG is not valid len
                            for x in range(1,7):
                                lines_de.pop()
                            continue

                        if (len(lines_de[-4]) != 33):
                            # If NONCE is not valid len
                            lines_de.append('FAILS = WRONG_NONCE_LENGTH\n')

                    lines_de.append(line)

    with open('third_party/NIST/CAVPGCM/' + file + '_ring.rsp', 'w') as outfile:
        for line in lines_de:
            outfile.write(line)

    # Empty list
    lines_de[:] = []
