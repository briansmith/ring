#!/usr/bin/python3

import argparse
import subprocess
import re
import sys

PCLMUL_RE = re.compile(r'^\s+[0-9a-f]+:\s+(?P<disas>(?:[0-9a-f][0-9a-f] )+)\s+vpclmul(?P<type>[0-9a-z]+)dq (?P<args>.*%[yz]mm.*)$')
NON_PCLMUL_RE = re.compile(r'^\s+[0-9a-f]+:\s+(?P<disas>(?:[0-9a-f][0-9a-f] )+)\s+(?P<instruction>vaesenc|vaesenclast) (?P<args>.*%[yz]mm.*)$')

TYPE_MAP = {
    'lqlq': 0x00,
    'lqhq': 0x10,
    'hqlq': 0x01,
    'hqhq': 0x11,
}

def hexify_disas(disas):
    return (' '+disas.strip()).replace(' ', ',0x')[1:]

def main():
    parser = argparse.ArgumentParser(
        prog='make-avx-map-for-old-binutils',
        description='Generate a map file for old binutils from .o files'
    )
    parser.add_argument('filename', nargs='+', help='object file to generate map from')
    parsed = parser.parse_args()
    for filename in parsed.filename:
        for line in subprocess.check_output(['objdump', '-d', filename], stderr=sys.stderr).decode('utf-8').split('\n'):
            if match := PCLMUL_RE.match(line):
                hexified_disas = hexify_disas(match.group('disas'))
                ty = TYPE_MAP[match.group('type')]
                args = match.group('args').replace(',', ', ')
                print(f"        'vpclmulqdq $0x{ty:02x}, {args}' => '.byte {hexified_disas}',")
            elif match := NON_PCLMUL_RE.match(line):
                hexified_disas = hexify_disas(match.group('disas'))
                args = match.group('args').replace(',', ', ')
                print(f"        '{match.group('instruction')} {args}' => '.byte {hexified_disas}',")


if __name__ == '__main__':
    main()
