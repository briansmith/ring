# this module contains all the defaults used by the generation of cleaned-up headers
# for the Bionic C library
#

import time, os, sys
from utils import *

# the list of supported architectures
kernel_archs = [ 'arm', 'arm64', 'mips', 'x86' ]

# the list of include directories that belong to the kernel
# tree. used when looking for sources...
kernel_dirs = [ "linux", "asm", "asm-generic", "mtd" ]

# a special value that is used to indicate that a given macro is known to be
# undefined during optimization
kCppUndefinedMacro = "<<<undefined>>>"

# this is the set of known macros we want to totally optimize out from the
# final headers
kernel_known_macros = {
    "__KERNEL__": kCppUndefinedMacro,
    "__KERNEL_STRICT_NAMES":"1",
    "__CHECKER__": kCppUndefinedMacro,
    "__CHECK_ENDIAN__": kCppUndefinedMacro,
    "CONFIG_64BIT": "__LP64__",
    "CONFIG_X86_32": "__i386__",
    "__EXPORTED_HEADERS__": "1",
    "__HAVE_BUILTIN_BSWAP16__": "1",
    "__HAVE_BUILTIN_BSWAP32__": "1",
    "__HAVE_BUILTIN_BSWAP64__": "1",
    }

# define to true if you want to remove all defined(CONFIG_FOO) tests
# from the clean headers. testing shows that this is not strictly necessary
# but just generates cleaner results
kernel_remove_config_macros = True

# maps an architecture to a set of default macros that would be provided by
# toolchain preprocessor
kernel_default_arch_macros = {
    "arm": {"__ARMEB__": kCppUndefinedMacro, "__ARM_EABI__": "1"},
    "arm64": {},
    "mips": {"__MIPSEB__": kCppUndefinedMacro,
             "__MIPSEL__": "1",
             "CONFIG_32BIT": "_ABIO32",
             "CONFIG_CPU_LITTLE_ENDIAN": "1",
             "__SANE_USERSPACE_TYPES__": "1",},
    "x86": {},
    }

kernel_arch_token_replacements = {
    "arm": {},
    "arm64": {},
    "mips": {"off_t":"__kernel_off_t"},
    "x86": {},
    }

# Replace tokens in the output according to this mapping.
kernel_token_replacements = {
    # The kernel usage of __unused for unused struct fields conflicts with the macro defined in <sys/cdefs.h>.
    "__unused": "__linux_unused",
    # The kernel usage of C++ keywords causes problems for C++ code so rename.
    "private": "__linux_private",
    "virtual": "__linux_virtual",
    # The non-64 stuff is legacy; msqid64_ds/ipc64_perm is what userspace wants.
    "msqid_ds": "__kernel_legacy_msqid_ds",
    "semid_ds": "__kernel_legacy_semid_ds",
    "shmid_ds": "__kernel_legacy_shmid_ds",
    "ipc_perm": "__kernel_legacy_ipc_perm",
    # The kernel semun isn't usable (https://github.com/android-ndk/ndk/issues/400).
    "semun": "__kernel_legacy_semun",
    # The kernel's _NSIG/NSIG are one less than the userspace value, so we need to move them aside.
    "_NSIG": "_KERNEL__NSIG",
    "NSIG": "_KERNEL_NSIG",
    # The kernel's SIGRTMIN/SIGRTMAX are absolute limits; userspace steals a few.
    "SIGRTMIN": "__SIGRTMIN",
    "SIGRTMAX": "__SIGRTMAX",
    # We want to support both BSD and Linux member names in struct udphdr.
    "udphdr": "__kernel_udphdr",
    # This causes problems when trying to export the headers for the ndk.
    "__attribute_const__": "__attribute__((__const__))",
    # In this case the kernel tries to keep out of our way, but we're happy to use its definition.
    "__kernel_sockaddr_storage": "sockaddr_storage",
    }


# This is the set of struct definitions that we want to replace with
# a #include of <bits/struct.h> instead.
kernel_struct_replacements = set(
        [
          "epoll_event",
          "in_addr",
          "ip_mreq_source",
          "ip_msfilter",
        ]
    )


# This is the set of known static inline functions that we want to keep
# in the final kernel headers.
kernel_known_generic_statics = set(
        [
          "ipt_get_target",  # uapi/linux/netfilter_ipv4/ip_tables.h
          "ip6t_get_target", # uapi/linux/netfilter_ipv6/ip6_tables.h
          # Byte swapping inlines from uapi/linux/swab.h
          # The below functions are the ones we are guaranting we export.
          "__swab16",
          "__swab32",
          "__swab64",
          "__swab16p",
          "__swab32p",
          "__swab64p",
          "__swab16s",
          "__swab32s",
          "__swab64s",
          "__swahw32",
          "__swahb32",
          "__swahw32p",
          "__swahb32p",
          "__swahw32s",
          "__swahb32s",
          # These are required to support the above functions.
          "__fswahw32",
          "__fswahb32",
        ]
    )

# this is the standard disclaimer
#
kernel_disclaimer = """\
/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ***   To edit the content of this header, modify the corresponding
 ***   source file (e.g. under external/kernel-headers/original/) then
 ***   run bionic/libc/kernel/tools/update_all.py
 ***
 ***   Any manual change here will be lost the next time this script will
 ***   be run. You've been warned!
 ***
 ****************************************************************************
 ****************************************************************************/
"""
