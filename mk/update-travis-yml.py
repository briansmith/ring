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

latest_clang = "clang-3.8"

rusts = [
    "stable",
    "nightly",
    "beta",
]

linux_compilers = [
    # GCC 4.6 is supported almost exclusively because it is the default
    # compiler for Ubuntu 12.04 LTS, and in particular Travis CI. This is run
    # first because it is the one most likely to break, especially since it is
    # not supported by BoringSSL.
    "gcc-4.6",

    # Pre-release of clang.
    "clang-3.8",

    # Newest clang and GCC.
    "clang-3.7",
    "gcc-5",

    # All other clang versions, newest to oldest.
    "clang-3.6",
    "clang-3.4",

    # All other GCC versions, newest to oldest.
    "gcc-4.9",
    "gcc-4.8",
]

# Clang 3.4 and GCC 4.6 are already installed by default.
linux_default_clang = "clang-3.4"
linux_default_gcc = "gcc-4.6"

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

targets = {
    "osx" : [
        "x86_64-apple-darwin",
    ],
    "linux" : [
        "i686-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
    ],
}

def format_entries():
    return "\n".join([format_entry(os, target, compiler, rust, mode)
                      for rust in rusts
                      for os in oss
                      for compiler in compilers[os]
                      for target in targets[os]
                      for mode in modes])

# We use alternative names (the "_X" suffix) so that, in mk/travis.sh, we can
# enure that we set the specific variables we want and that no relevant
# variables are unintentially inherited into the build process. Also, we have
# to set |USE_CC| and |USE_CXX| instead of |CC| and |CXX| since Travis sets
# |CC| and |CXX| to their default values *after* processing the |env:|
# directive here. Also, we keep these variable names short so that the env
# line does not get cut off in the Travis CI UI.
entry_template = """
    - env: TARGET_X=%(target)s CC_X=%(cc)s CXX_X=%(cxx)s MODE_X=%(mode)s
      rust: %(rust)s
      os: %(os)s"""

entry_indent = "      "

entry_packages_template = """
      addons:
        apt:
          packages:
            %(packages)s"""

entry_sources_template = """
          sources:
            %(sources)s"""

def format_entry(os, target, compiler, rust, mode):
    target_words = target.split("-")
    arch = target_words[0]
    vendor = target_words[1]
    sys = target_words[2]

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

    if os == "osx":
        os += "\n" + entry_indent + "osx_image: xcode7.2"

    return template % {
            "cc" : cc,
            "cxx" : cxx,
            "mode" : mode,
            "packages" : "\n            ".join(prefix_all("- ", packages)),
            "rust" : rust,
            "sources" : "\n            ".join(prefix_all("- ", sources)),
            "target" : target,
            "os" : os,
            }

def get_linux_packages_to_install(compiler, arch):
    if compiler in [linux_default_clang, linux_default_gcc]:
        packages = []
    elif compiler.startswith("clang-"):
        packages = [compiler]
    elif compiler.startswith("gcc-"):
        packages = [compiler, replace_cc_with_cxx("linux", compiler)]
    else:
        raise ValueError("unexpected compiler: %s" % compiler)

    if arch == "i686":
        if compiler.startswith("clang-") or compiler == linux_default_gcc:
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

    return packages

def get_sources_for_package(package):
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
    if sys == "linux" and compiler == linux_default_clang:
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
