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

linux_compilers = [
    # Since Travis CI limits the number of concurrent builds, we put the
    # highest-signal (most likely to break) builds first, to reduce latency
    # in discovering broken builds.
    #
    # XXX TODO: clang-3.7 was available and working using this setup, but for
    # some reason it isn't working any more as of 2015-07-24, so it has been
    # removed from the matrix for now.
    "clang-3.6", # Newest clang first.
    "gcc-4.8",   # Oldest GCC next.

    # All other clang versions, newest to oldest.
    "clang-3.5",
    "clang-3.4",

    # All other GCC versions, newest to oldest.
    "gcc-5",
    "gcc-4.9",
]

osx_compilers = [
     "clang",
]

compilers = {
    "linux" : linux_compilers,
    "osx" : osx_compilers,
}

modes = [
    "DEBUG",
    "RELWITHDEBINFO"
]

# Mac OS X is first because we don't want to have to wait until all the Linux
# configurations have been built to find out that there is a failure on Mac.
oss = [
    "osx",
    "linux",
]

# The second vlaue in each tuple is the value of the NO_ASM paramter.
targets = {
    "osx" : [
        ("x86_64-apple-darwin-macho", ""),
        ("x86-apple-darwin-macho", ""),
    ],
    "linux" : [
        ("x86_64-pc-linux-gnu", ""),
        ("x86-pc-linux-gnu", ""),
        ("x86_64-pc-linux-gnu", "1"),
        ("x86-pc-linux-gnu", "1"),
    ],
}

no_asms = [
    "",
    "1",
]

def format_entries():
    return "\n".join([format_entry(os, target, compiler, no_asm, mode)
                      for os in oss
                      for target, no_asm in targets[os]
                      for compiler in compilers[os]
                      for mode in modes
                      # XXX: 32-bit GCC 4.9 does not work because Travis does
                      # not have g++-4.9-multilib whitelisted for use.
                      if not (compiler == "gcc-4.9" and
                              target == "x86-pc-linux-gnu")])

# Set |USE_CC| and |USE_CXX| instead of |CC| and |CXX| since Travis sets |CC|
# and |CXX| to its default values *after* processing the |env:| directive here.
# The travis |before_script| section will then |export CC=$USE_CC CXX=$USE_CXX|.
entry_template = """
    - env: TARGET=%(target)s USE_CC=%(cc)s USE_CXX=%(cxx)s CMAKE_BUILD_TYPE=%(mode)s
      os: %(os)s"""

entry_packages_template = """
      addons:
        apt:
          packages:
            %(packages)s"""

entry_sources_template = """
          sources:
            %(sources)s"""

def format_entry(os, target, compiler, no_asm, mode):
    arch, vendor, sys, abi = target.split("-")

    def prefix_all(prefix, xs):
        return [prefix + x for x in xs]

    template = entry_template

    if sys == "linux":
        packages = sorted(get_linux_packages_to_install(compiler, arch))
        sources_with_dups = sum([get_sources_for_package(p) for p in packages],[])
        sources = sorted(list(set(sources_with_dups)))
        if packages:
            template += entry_packages_template
        if sources:
            template += entry_sources_template
    else:
        packages = []
        sources = []

    cc = get_cc(sys, compiler)
    cxx = replace_cc_with_cxx(sys, compiler)

    return template % {
            "cc" : cc,
            "cxx" : cxx,
            "mode" : mode,
            "packages" : "\n            ".join(prefix_all("- ", packages)),
            "sources" : "\n            ".join(prefix_all("- ", sources)),
            "target" : target + ("" if not no_asm else (" NO_ASM=" + no_asm)),
            "os" : os,
            }

def get_linux_packages_to_install(compiler, arch):
    # clang 3.4 is already installed
    if compiler == "clang-3.4":
        packages = []
    elif compiler.startswith("clang-"):
        packages = [compiler]
    elif compiler.startswith("gcc-"):
        packages = [compiler, replace_cc_with_cxx("linux", compiler)]
    else:
        raise ValueError("unexpected compiler: %s" % compiler)

    if arch == "x86":
        if compiler.startswith("clang-"):
            packages += ["libc6-dev-i386",
                         "gcc-multilib",
                         "g++-multilib"]
        elif compiler.startswith("gcc-"):
            packages += [compiler + "-multilib",
                         replace_cc_with_cxx("linux", compiler) + "-multilib",
                         "linux-libc-dev:i386"]
        else:
            raise ValueError("unexpected compiler: %s" % compiler)
    elif arch == "x86_64":
        pass
    else:
        raise ValueError("unexpected arch: %s" % arch)

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

def get_cc(sys, compiler):
    if sys == "linux" and compiler == "clang-3.4":
        return "clang"

    return compiler

def replace_cc_with_cxx(sys, compiler):
    return get_cc(sys, compiler) \
               .replace("gcc", "g++") \
               .replace("clang", "clang++")

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
