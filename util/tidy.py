# Copyright 2013 The Servo Project Developers.
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

import fnmatch
import itertools
import os
import re

URL_COMMENT = re.compile("^ *///? https?:\S+$")
MAX_LINE_LENGTH = 90


# File patterns to include in the tidy check.
file_patterns_to_check = ["*.rs", "*.cpp", "*.c",
                          "*.h", "Cargo.lock", "*.py",
                          "*.toml"]

# File patterns that are ignored for all tidy and lint checks.
file_patterns_to_ignore = [
    "*.#*",
    "*.pyc",
]

# Files that are ignored for all tidy and lint checks.
ignored_files = [
    # Hidden files
    os.path.join(".", "."),
]

# Directories that are ignored for the non-WPT tidy check.
ignored_dirs = [
    # Imported from BoringSSL
    os.path.join(".", "crypto"),
    os.path.join(".", "include", "openssl"),
    # Hidden directories
    os.path.join(".", "."),
]


def filter_file(file_name):
    if any(file_name.startswith(ignored_file)
           for ignored_file in ignored_files):
        return False
    base_name = os.path.basename(file_name)
    if any(fnmatch.fnmatch(base_name, pattern)
           for pattern in file_patterns_to_ignore):
        return False
    return True


def filter_files(start_dir):
    file_iter = get_file_list(start_dir, ignored_dirs)
    for file_name in file_iter:
        base_name = os.path.basename(file_name)
        if not any(fnmatch.fnmatch(base_name, pattern)
                   for pattern in file_patterns_to_check):
            continue
        if not filter_file(file_name):
            continue
        yield file_name


def check_length(file_name, idx, line):
    if file_name.endswith(".lock") or file_name.endswith(".json"):
        raise StopIteration
    if len(line.rstrip('\n')) > MAX_LINE_LENGTH \
            and not URL_COMMENT.match(line):
        yield (idx + 1, "Line is longer than %d characters" % MAX_LINE_LENGTH)


def check_whitespace(idx, line):
    if line[-1] == "\n":
        line = line[:-1]
    else:
        yield (idx + 1, "no newline at EOF")

    if line.endswith(" "):
        yield (idx + 1, "trailing whitespace")

    if "\t" in line:
        yield (idx + 1, "tab on line")

    if "\r" in line:
        yield (idx + 1, "CR on line")


def check_by_line(file_name, lines):
    for idx, line in enumerate(lines):
        errors = itertools.chain(
            check_length(file_name, idx, line),
            check_whitespace(idx, line),
        )

        for error in errors:
            yield error


def collect_errors_for_files(files_to_check, checking_functions,
                             line_checking_functions):
    for filename in files_to_check:
        with open(filename, "r") as f:
            contents = f.read()
            for check in checking_functions:
                for error in check(filename, contents):
                    # the result will be: `(filename, line, message)`
                    yield (filename,) + error
            lines = contents.splitlines(True)
            for check in line_checking_functions:
                for error in check(filename, lines):
                    yield (filename,) + error


def get_file_list(directory, exclude_dirs=[]):
    if exclude_dirs:
        for root, dirs, files in os.walk(directory, topdown=True):
            # modify 'dirs' in-place so that we don't do
            # unwanted traversals in excluded directories
            dirs[:] = [d for d in dirs
                       if not any(os.path.join(root, d).startswith(name)
                                  for name in ignored_dirs)]
            for rel_path in files:
                yield os.path.join(root, rel_path)
    else:
        for root, _, files in os.walk(directory):
            for f in files:
                yield os.path.join(root, f)


def scan():
    # standard checks
    files_to_check = filter_files('.')
    checking_functions = ()
    line_checking_functions = (check_by_line,)
    errors = collect_errors_for_files(files_to_check, checking_functions,
                                      line_checking_functions)

    error = None
    for error in errors:
        print "\r\033[94m{}\033[0m:\033[93m{}\033[0m: \033[91m{}\033[0m" \
            .format(*error)
    if error is None:
        print "\033[92mtidy reported no errors.\033[0m"
    return int(error is not None)

if __name__ == '__main__':
    scan()
