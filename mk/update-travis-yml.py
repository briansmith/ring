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

clang = "clang-10"

# GCC 4.8 and GCC 9 are tested in less thoroughly in configurations hard-coded
# in .travis.yml.
linux_compilers = [
    clang,
]

apple_compilers = [
     "", # Don't set CC.'
]

feature_sets = [
    "",
]

modes = [
    "DEBUG",
    "RELWITHDEBINFO"
]

# Mac OS X is first because we don't want to have to wait until all the Linux
# configurations have been built to find out that there is a failure on Mac.
targets = {
    "osx" : [
        ("aarch64-apple-ios", apple_compilers),
        ("x86_64-apple-darwin", apple_compilers),
    ],
    "linux" : [
        ("aarch64-linux-android", [ "aarch64-linux-android21-clang" ]),
        ("armv7-linux-androideabi", [ "armv7a-linux-androideabi18-clang" ]),
        ("x86_64-unknown-linux-gnu", linux_compilers),
        ("x86_64-unknown-linux-musl", [clang]),
        ("aarch64-unknown-linux-gnu", [ "aarch64-linux-gnu-gcc" ]),
        ("i686-unknown-linux-gnu", linux_compilers),
        ("i686-unknown-linux-musl", [clang]),
        ("arm-unknown-linux-gnueabihf", [ "arm-linux-gnueabihf-gcc" ]),
    ],
}

def kcovs(target, rust, mode):
    # DEBUG mode is needed because debug symbols are needed for coverage tracking.
    # Nightly Rust is needed for `-Zpanic_abort_tests -Zprofile`.
    kcov_targets = ["x86_64-unknown-linux-gnu", "i686-unknown-linux-gnu"]
    return [False, True] if target in kcov_targets and rust == "nightly" and mode == "DEBUG" else [False]

def format_entries():
    return "\n".join([format_entry(os, target, compiler, rust, mode, features, kcov)
                      for rust in rusts
                      for os in targets.keys()
                      for (target, compilers) in targets[os]
                      for compiler in compilers
                      for mode in modes
                      for features in feature_sets
                      for kcov in kcovs(target, rust, mode)])

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

def format_entry(os, target, compiler, rust, mode, features, kcov):
    target_words = target.split("-")
    arch = target_words[0]
    vendor = target_words[1]
    sys = target_words[2]

    template = entry_template

    linux_dist = "focal"
    android_linux_dist = "trusty"

    if sys == "darwin":
        abi = sys
        sys = "macos"
    elif sys == "ios":
        abi = sys
        sys = "ios"
    elif sys == "androideabi":
        linux_dist = android_linux_dist
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
        linux_dist = android_linux_dist
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
        template += """
      dist: %s""" % linux_dist

    if sys == "linux":
        if packages:
            template += entry_packages_template
    else:
        packages = []

    cc = compiler

    if os == "osx":
        os += "\n" + entry_indent + "osx_image: xcode12"

    compilers = []
    if cc != "":
        compilers += ["CC_X=" + cc]
    compilers += ""

    return template % {
            "compilers": " ".join(compilers),
            "features" : features,
            "mode" : mode,
            "kcov": "1" if kcov else "0",
            "packages" : "\n            ".join(prefix_all("- ", packages)),
            "rust" : rust,
            "target" : target,
            "os" : os,
            }

def get_linux_packages_to_install(target, compiler, arch, kcov):
    if compiler.startswith("clang-") or compiler.startswith("gcc-"):
        packages = [compiler]
    else:
        packages = []

    if kcov:
        packages += ["kcov"]

    qemu = False

    if target == "aarch64-unknown-linux-gnu":
        qemu = True
        packages += ["gcc-aarch64-linux-gnu",
                     "libc6-dev-arm64-cross"]
    if target == "arm-unknown-linux-gnueabihf":
        qemu = True
        packages += ["gcc-arm-linux-gnueabihf",
                     "libc6-dev-armhf-cross"]

    if qemu:
        packages += ["binfmt-support",
                     "qemu-user-binfmt"]

    if arch == "i686":
        if compiler.startswith("clang") or compiler == "":
            packages += ["libc6-dev-i386",
                         "gcc-multilib"]
        elif compiler.startswith("gcc-"):
            packages += [compiler + "-multilib",
                         "linux-libc-dev:i386"]
        else:
            raise ValueError("unexpected compiler: %s" % compiler)

    return packages

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
