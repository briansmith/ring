# Run this as "python mk/update-travis-yml.py"

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

import re
import shutil

latest_clang = "clang-3.7"

compilers = [
    # Since Travis CI limits the number of concurrent builds, we put the
    # highest-signal (most likely to break) builds first, to reduce latency
    # in discovering broken builds.
    latest_clang, # Newest clang first.
    "gcc-4.8",   # Oldest GCC next.

    # All other clang versions, newest to oldest.
    "clang-3.6",
    "clang-3.5",
    "clang-3.4",

    # All other GCC versions, newest to oldest.
    "gcc-5",
    "gcc-4.9",
]

modes = [
    "DEBUG",
    "RELWITHDEBINFO"
]

bits_choices = [
    "64",
    "32",
]

def format_entries():
    return "\n".join([format_entry(compiler, mode, bits)
                      for mode in modes
                      for bits in bits_choices
                      for compiler in compilers
                      # XXX: 32-bit GCC 4.9 does not work because Travis does
                      # not have g++-4.9-multilib whitelisted for use.
                      if not (compiler == "gcc-4.9" and bits == "32")])

entry_template = """
    - env: %(uppercase)s_VERSION=%(version)s CMAKE_BUILD_TYPE=%(mode)s BITS=%(bits)s
      os: linux
      addons:
        apt:
          packages:
            %(packages)s"""

entry_sources_template = """
          sources:
            %(sources)s"""

def format_entry(compiler, mode, bits):
    def prefix_all(prefix, xs):
        return [prefix + x for x in xs]

    packages = sorted(get_packages_to_install(compiler, bits))
    sources_with_dups = sum([get_sources_for_package(p) for p in packages],[])
    sources = sorted(list(set(sources_with_dups)))
    (compiler_name, compiler_version) = compiler.split("-")
    template = entry_template
    if sources:
        template += entry_sources_template

    return template % {
            "uppercase" : compiler_name.upper(),
            "version" : compiler_version,
            "mode" : mode,
            "bits" : bits,
            "packages" : "\n            ".join(prefix_all("- ", packages)),
            "sources" : "\n            ".join(prefix_all("- ", sources)),
            }

def get_packages_to_install(compiler, bits):
    # clang 3.4 is already installed
    if compiler == "clang-3.4":
        packages = []
    elif compiler.startswith("clang-"):
        packages = [compiler]
    elif compiler.startswith("gcc-"):
        packages = [compiler, replace_cc_with_cxx(compiler)]
    else:
        raise ValueError("unexpected compiler: %s" % compiler)

    if bits == "32":
        if compiler.startswith("clang-"):
            packages += ["libc6-dev-i386",
                         "gcc-multilib",
                         "g++-multilib"]
        elif compiler.startswith("gcc-"):
            packages += [compiler + "-multilib",
                         replace_cc_with_cxx(compiler) + "-multilib",
                         "linux-libc-dev:i386"]
        else:
            raise ValueError("unexpected compiler: %s" % compiler)

    packages.append("yasm")

    return packages

def get_sources_for_package(package):
    # Packages in the default repo.
    if package in ["yasm"]:
        return []

    ubuntu_toolchain = "ubuntu-toolchain-r-test"
    if package.startswith("clang-"):
        if package == latest_clang:
            llvm_toolchain = "llvm-toolchain-precise"
        else:
            _, version = package.split("-")
            llvm_toolchain = "llvm-toolchain-precise-%s" % version

        # Stuff in llvm-toolchain-precise depends on stuff in the toolchain
        # packages.
        return [llvm_toolchain, ubuntu_toolchain]
    else:
        return [ubuntu_toolchain]

def get_cc(compiler):
    return compiler if compiler != "clang-3.4" else "clang"

def replace_cc_with_cxx(compiler):
    return get_cc(compiler).replace("gcc", "g++").replace("clang", "clang++")

def main():
    # Make a backup of the file we are about to update.
    shutil.copyfile(".travis.yml", ".travis.yml~")
    with open(".travis.yml", "r+b") as file:
        begin = "    # BEGIN GENERATED\n"
        end = "    # END GENERATED\n"
        old_contents = file.read()
        new_contents = re.sub("%s(.*?)\n[ ]*%s" % (begin, end),
                              "".join([begin, format_entries(), "\n\n", end]),
                              old_contents, flags=re.S)
        if old_contents == new_contents:
            print "No changes"
            return

        file.seek(0)
        file.write(new_contents)
        file.truncate()
        print new_contents

if __name__ == '__main__':
    main()
