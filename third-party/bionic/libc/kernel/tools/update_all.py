#!/usr/bin/env python
#
import sys, cpp, kernel, glob, os, re, getopt, clean_header, subprocess, shutil
from defaults import *
from utils import *

def usage():
    print """\
  usage: %(progname)s [kernel-original-path] [kernel-modified-path]

    this program is used to update all the auto-generated clean headers
    used by the Bionic C library. it assumes the following:

      - a set of source kernel headers is located in
        'external/kernel-headers/original', relative to the current
        android tree

      - a set of manually modified kernel header files located in
        'external/kernel-headers/modified', relative to the current
        android tree

      - the clean headers will be placed in 'bionic/libc/kernel/arch-<arch>/asm',
        'bionic/libc/kernel/android', etc..
""" % { "progname" : os.path.basename(sys.argv[0]) }
    sys.exit(0)

def processFiles(updater, original_dir, modified_dir, src_rel_dir, update_rel_dir):
    # Delete the old headers before updating to the new headers.
    update_dir = os.path.join(get_kernel_dir(), update_rel_dir)
    shutil.rmtree(update_dir)
    os.mkdir(update_dir, 0755)

    src_dir = os.path.normpath(os.path.join(original_dir, src_rel_dir))
    src_dir_len = len(src_dir) + 1
    mod_src_dir = os.path.join(modified_dir, src_rel_dir)
    update_dir = os.path.join(get_kernel_dir(), update_rel_dir)

    kernel_dir = get_kernel_dir()
    for root, _, files in os.walk(src_dir):
        for file in sorted(files):
            _, ext = os.path.splitext(file)
            if ext != ".h":
                continue
            src_file = os.path.normpath(os.path.join(root, file))
            rel_path = src_file[src_dir_len:]
            # Check to see if there is a modified header to use instead.
            if os.path.exists(os.path.join(mod_src_dir, rel_path)):
                src_file = os.path.join(mod_src_dir, rel_path)
                src_str = os.path.join("<modified>", src_rel_dir, rel_path)
            else:
                src_str = os.path.join("<original>", src_rel_dir, rel_path)
            dst_file = os.path.join(update_dir, rel_path)
            new_data = clean_header.cleanupFile(dst_file, src_file, rel_path)
            if not new_data:
                continue
            updater.readFile(dst_file)
            ret_val = updater.editFile(dst_file, new_data)
            if ret_val == 0:
                state = "unchanged"
            elif ret_val == 1:
                state = "edited"
            else:
                state = "added"
            update_path = os.path.join(update_rel_dir, rel_path)
            print "cleaning %s -> %s (%s)" % (src_str, update_path, state)

try:
    optlist, args = getopt.getopt(sys.argv[1:], '')
except:
    # Unrecognized option
    sys.stderr.write("error: unrecognized option\n")
    usage()

if len(optlist) > 0 or len(args) > 2:
    usage()

if len(args) > 0:
    original_dir = args[0]
else:
    original_dir = get_kernel_headers_original_dir()

if len(args) > 1:
    modified_dir = args[1]
else:
    modified_dir = get_kernel_headers_modified_dir()

if not os.path.isdir(original_dir):
    panic("The kernel directory %s is not a directory\n" % original_dir)

if not os.path.isdir(modified_dir):
    panic("The kernel modified directory %s is not a directory\n" % modified_dir)

updater = BatchFileUpdater()
# Process the original uapi headers first.
processFiles(updater, original_dir, modified_dir, "uapi", "uapi"),

# Now process the special files.
processFiles(updater, original_dir, modified_dir, "scsi", os.path.join("android", "scsi", "scsi"))

updater.updateGitFiles()
