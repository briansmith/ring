#!/usr/bin/env python

#------------------------------------------------------------------------------
# Description of the header clean process
#------------------------------------------------------------------------------
# Here is the list of actions performed by this script to clean the original
# kernel headers.
#
# 1. Optimize well-known macros (e.g. __KERNEL__, __KERNEL_STRICT_NAMES)
#
#     This pass gets rid of everything that is guarded by a well-known macro
#     definition. This means that a block like:
#
#        #ifdef __KERNEL__
#        ....
#        #endif
#
#     Will be totally omitted from the output. The optimizer is smart enough to
#     handle all complex C-preprocessor conditional expression appropriately.
#     This means that, for example:
#
#        #if defined(__KERNEL__) || defined(FOO)
#        ...
#        #endif
#
#     Will be transformed into:
#
#        #ifdef FOO
#        ...
#        #endif
#
#     See tools/defaults.py for the list of well-known macros used in this pass,
#     in case you need to update it in the future.
#
#     Note that this also removes any reference to a kernel-specific
#     configuration macro like CONFIG_FOO from the clean headers.
#
#
# 2. Remove variable and function declarations:
#
#   This pass scans non-directive text and only keeps things that look like a
#   typedef/struct/union/enum declaration. This allows us to get rid of any
#   variables or function declarations that should only be used within the
#   kernel anyway (and which normally *should* be guarded by an #ifdef
#   __KERNEL__ ...  #endif block, if the kernel writers were not so messy).
#
#   There are, however, a few exceptions: it is seldom useful to keep the
#   definition of some static inline functions performing very simple
#   operations. A good example is the optimized 32-bit byte-swap function
#   found in:
#
#     arch-arm/asm/byteorder.h
#
#   The list of exceptions is in tools/defaults.py in case you need to update
#   it in the future.
#
#   Note that we do *not* remove macro definitions, including these macro that
#   perform a call to one of these kernel-header functions, or even define other
#   functions. We consider it safe since userland applications have no business
#   using them anyway.
#
#
# 3. Add a standard disclaimer:
#
#   The message:
#
#   /* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#
#   Is prepended to each generated header.
#------------------------------------------------------------------------------

import sys, cpp, kernel, glob, os, re, getopt
from defaults import *
from utils import *

def print_error(no_update, msg):
    if no_update:
        panic(msg)
    sys.stderr.write("warning: " + msg)


def cleanupFile(dst_file, src_file, rel_path, no_update = True):
    """reads an original header and perform the cleanup operation on it
       this functions returns the destination path and the clean header
       as a single string"""
    # Check the header path
    if not os.path.exists(src_file):
        print_error(no_update, "'%s' does not exist\n" % src_file)
        return None, None

    if not os.path.isfile(src_file):
        print_error(no_update, "'%s' is not a file\n" % src_file)
        return None, None

    # Extract the architecture if found.
    arch = None
    m = re.search(r"(^|/)asm-([\w\d_\+\.\-]+)/.*", rel_path)
    if m and m.group(2) != 'generic':
        arch = m.group(2)

    # Now, let's parse the file.
    parser = cpp.BlockParser()
    blocks = parser.parseFile(src_file)
    if not parser.parsed:
        print_error(no_update, "Can't parse '%s'" % src_file)
        return None

    macros = kernel_known_macros.copy()
    if arch and arch in kernel_default_arch_macros:
        macros.update(kernel_default_arch_macros[arch])

    if arch and arch in kernel_arch_token_replacements:
        blocks.replaceTokens(kernel_arch_token_replacements[arch])

    blocks.optimizeMacros(macros)
    blocks.optimizeIf01()
    blocks.removeVarsAndFuncs(kernel_known_generic_statics)
    blocks.replaceTokens(kernel_token_replacements)

    out = StringOutput()
    out.write(kernel_disclaimer)
    blocks.write(out)
    return out.get()


if __name__ == "__main__":

    def usage():
        print """\
    usage:  %s [options] <header_path>

        options:
            -v    enable verbose mode

            -u    enabled update mode
                this will try to update the corresponding 'clean header'
                if the content has changed. with this, you can pass more
                than one file on the command-line

            -k<path>  specify path of original kernel headers
            -d<path>  specify path of cleaned kernel headers

        <header_path> must be in a subdirectory of 'original'
    """ % os.path.basename(sys.argv[0])
        sys.exit(1)

    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'uvk:d:')
    except:
        # unrecognized option
        sys.stderr.write("error: unrecognized option\n")
        usage()

    no_update = True
    dst_dir = get_kernel_dir()
    src_dir = get_kernel_headers_original_dir()
    for opt, arg in optlist:
        if opt == '-u':
            no_update = False
        elif opt == '-v':
            logging.basicConfig(level=logging.DEBUG)
        elif opt == '-k':
            src_dir = arg
        elif opt == '-d':
            dst_dir = arg

    if len(args) == 0:
        usage()

    if no_update:
        for path in args:
            dst_file = os.path.join(dst_dir, path)
            src_file = os.path.join(src_dir, path)
            new_data = cleanupFile(dst_file, src_file, path)
            print new_data

        sys.exit(0)

    # Now let's update our files.

    b = BatchFileUpdater()

    for path in args:
        dst_file = os.path.join(dst_dir, path)
        src_file = os.path.join(src_dir, path)
        new_data = cleanupFile(dst_file, src_file, path, no_update)
        if not new_data:
            continue

        b.readFile(path)
        r = b.editFile(path, new_data)
        if r == 0:
            r = "unchanged"
        elif r == 1:
            r = "edited"
        else:
            r = "added"

        print "cleaning: %-*s -> %-*s (%s)" % (35, path, 35, path, r)


    b.updateGitFiles()

    sys.exit(0)
