# Copyright 2015 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
# BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import print_function
import argparse
import json
import os
import subprocess
import sys

def run_tests(build_dir_path):
    with open("util/all_tests.json", "rb") as f:
        file_contents = json.loads(f.read())
    
    # file_contents is an array of arrays of strings.
    failures = []
    for command in file_contents:
        command[0] = os.path.join(build_dir_path, command[0])
        command_str = " ".join(command)
        print("Running %s" % command_str)
        exit_code = subprocess.call(command)
        if exit_code != 0:
            failures += ["%s failed with exit code %d" % (command_str, exit_code)]
    
    if failures:
        print("\n".join(failures), file=sys.stderr)
        sys.exit("%d tests failed" % len(failures))
    
    print("All tests passed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run tests.")
    parser.add_argument('-build-dir', required=True)
    args = parser.parse_args()
    run_tests(args.build_dir)
