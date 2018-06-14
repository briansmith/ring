#!/usr/bin/env python3

import os
import subprocess
import sys

INVALID_SYMBOLS = {
    '_GLOBAL_OFFSET_TABLE_', 'stderr', 'stdout', 'fprintf', 'malloc', 'free',
    'memset', 'memcpy', 'memcmp', 'memmove', 'syscall', 'getauxval',
    'DW.ref.rust_eh_personality', 'rust_eh_personality', '_Unwind_Resume'
}

def get_version_suffix():
    # Get githash
    githash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('utf-8')

    # Get package version line from Cargo.toml
    with open('Cargo.toml', 'r') as fp:
        version_line = [l for l in fp.read().split('\n') if 'version' in l][0]

    # Extract version from that line and replace '.' and '-' with '_'
    version = version_line.split('"')[1].replace('.', '_').replace('-', '_')

    # Build suffix string from version and githash
    suffix = 'v{}_{}'.format(version, githash)[:23]
    return suffix

def is_valid_symbol(sym):
    return not ']:' in sym and not '::' in sym and not sym.startswith('__') and len(sym) > 0

def get_symbols(f):
    # Get all global demnagled symbols from the target file
    raw_symbols = subprocess.check_output(['nm', '-g', '--demangle', '-f', 'posix', f], stderr=subprocess.DEVNULL).decode('utf-8').split('\n')

    # Filter out some unneeded lines and decode to regular string
    raw_symbols = [s for s in raw_symbols if is_valid_symbol(s)]

    # Extract symbol substring from lines and remove duplicates
    symbols = list(set(s.split(' ')[0] for s in raw_symbols))

    return symbols

def check_symbols(f):
    # Get symbol suffix
    suffix = get_version_suffix()
    # Get symbols
    symbols = get_symbols(f)

    # Filter symbols with suffix and invalid symbols (C and asm related)
    filtered = [s for s in symbols if s not in INVALID_SYMBOLS and suffix not in s]

    print("Found {} symbols without suffix: {}".format(len(filtered), suffix))
    for s in filtered:
        print(s)

    return len(filtered)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("{} <path to 'libring.rlib'>".format(__file__))
        sys.exit(1)

    if check_symbols(sys.argv[1]) > 0:
        exit(1)
