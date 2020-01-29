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

rusts = [
    "stable",
    "nightly",
    "beta",
]

gcc = "gcc-7"
#Clang 5.0 is the default compiler on Travis CI for Ubuntu 14.04.
clang = "clang"

linux_compilers = [
    # Assume the default compiler is GCC.
    # GCC 4.8 is the default compiler on Travis CI for Ubuntu 14.04.
    "",

    clang,

    gcc,
]

osx_compilers = [
     "", # Don't set CC.'
]

compilers = {
    "aarch64-unknown-linux-gnu" : [ "aarch64-linux-gnu-gcc" ],
    "aarch64-linux-android" : [ "aarch64-linux-android21-clang" ],
    "armv7-linux-androideabi" : [ "armv7a-linux-androideabi18-clang" ],
    "arm-unknown-linux-gnueabihf" : [ "arm-linux-gnueabihf-gcc" ],
    "i686-unknown-linux-gnu" : linux_compilers,
    "x86_64-unknown-linux-gnu" : linux_compilers,
    "x86_64-apple-darwin" : osx_compilers,
}

feature_sets = [
    "",
]

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
        "aarch64-linux-android",
        "armv7-linux-androideabi",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "i686-unknown-linux-gnu",
        "arm-unknown-linux-gnueabihf",
    ],
}

def format_entries():
    return "\n".join([format_entry(os, target, compiler, rust, mode, features)
                      for rust in rusts
                      for os in oss
                      for target in targets[os]
                      for compiler in compilers[target]
                      for mode in modes
                      for features in feature_sets])

# We use alternative names (the "_X" suffix) so that, in mk/travis.sh, we can
# ensure that we set the specific variables we want and that no relevant
# variables are unintentially inherited into the build process. Also, we have
# to set |CC_X| instead of |CC| since Travis sets |CC| to its Travis CI default
# value *after* processing the |env:| directive here.
entry_template = """
    - env: TARGET_X=%(target)s %(compilers)s FEATURES_X=%(features)s MODE_X=%(mode)s KCOV=%(kcov)s RUST_X=%(rust)s
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

def format_entry(os, target, compiler, rust, mode, features):
    target_words = target.split("-")
    arch = target_words[0]
    vendor = target_words[1]
    sys = target_words[2]

    # Currently kcov only runs on Linux.
    #
    # GCC 7 was picked arbitrarily to restrict coverage report to one build for
    # efficiency reasons.
    #
    # DEBUG mode is needed because debug symbols are needed for coverage
    # tracking.
    kcov = (os == "linux" and compiler == gcc and rust == "nightly" and
            mode == "DEBUG")

    template = entry_template

    if sys == "darwin":
        abi = sys
        sys = "macos"
    elif sys == "androideabi":
        abi = sys
        sys = "linux"
        template += """
      language: android
      android:
        components:
        - android-18
        - build-tools-26.0.2
        - sys-img-armeabi-v7a-android-18"""
    elif sys == "android":
        abi = sys
        sys = "linux"
        template += """
      language: android
      android:
        components:
        - android-21
        - build-tools-26.0.2"""
    else:
        abi = target_words[3]

    def prefix_all(prefix, xs):
        return [prefix + x for x in xs]

    if sys == "linux":
        packages = sorted(get_linux_packages_to_install(target, compiler, arch, kcov))
        sources_with_dups = sum([get_sources_for_package(p) for p in packages],[])
        sources = sorted(list(set(sources_with_dups)))
        template += """
      dist: trusty"""

    if sys == "linux":
        if packages:
            template += entry_packages_template
        if sources:
            template += entry_sources_template
    else:
        packages = []
        sources = []

    cc = compiler

    if os == "osx":
        os += "\n" + entry_indent + "osx_image: xcode10.1"

    compilers = []
    if cc != "":
        compilers += ["CC_X=" + cc]
    compilers += ""

    return template % {
            "compilers": " ".join(compilers),
            "features" : features,
            "mode" : mode,
            "kcov": "1" if kcov == True else "0",
            "packages" : "\n            ".join(prefix_all("- ", packages)),
            "rust" : rust,
            "sources" : "\n            ".join(prefix_all("- ", sources)),
            "target" : target,
            "os" : os,
            }

def get_linux_packages_to_install(target, compiler, arch, kcov):
    if compiler.startswith("clang-") or compiler.startswith("gcc-"):
        packages = [compiler]
    else:
        packages = []

    if kcov:
        packages += [replace_cc_with_cxx(compiler)]

    if target == "aarch64-unknown-linux-gnu":
        packages += ["gcc-aarch64-linux-gnu",
                     "libc6-dev-arm64-cross"]
    if target == "arm-unknown-linux-gnueabihf":
        packages += ["gcc-arm-linux-gnueabihf",
                     "libc6-dev-armhf-cross"]

    if arch == "i686":
        if kcov == True:
            packages += [replace_cc_with_cxx(compiler) + "-multilib",
                         "libcurl3:i386",
                         "libcurl4-openssl-dev:i386",
                         "libdw-dev:i386",
                         "libelf-dev:i386",
                         "libiberty-dev:i386",
                         "libkrb5-dev:i386",
                         "libssl-dev:i386"]

        if compiler.startswith("clang") or compiler == "":
            packages += ["libc6-dev-i386",
                         "gcc-multilib"]
        elif compiler.startswith("gcc-"):
            packages += [compiler + "-multilib",
                         "linux-libc-dev:i386"]
        else:
            raise ValueError("unexpected compiler: %s" % compiler)
    elif arch == "x86_64":
        if kcov == True:
            packages += ["libcurl4-openssl-dev",
                         "libelf-dev",
                         "libdw-dev",
                         "binutils-dev",
                         "libiberty-dev"]
    elif arch not in ["aarch64", "arm", "armv7"]:
        raise ValueError("unexpected arch: %s" % arch)

    return packages

def get_sources_for_package(package):
    ubuntu_toolchain = "ubuntu-toolchain-r-test"
    if package.startswith("clang-"):
        _, version = package.split("-")
        llvm_toolchain = "llvm-toolchain-trusty-%s" % version

        # Stuff in llvm-toolchain-trusty depends on stuff in the toolchain
        # packages.
        return [llvm_toolchain, ubuntu_toolchain]
    elif package.startswith("gcc-"):
        return [ubuntu_toolchain]
    else:
        return []

def replace_cc_with_cxx(compiler):
    return compiler \
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
