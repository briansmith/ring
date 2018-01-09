# common python utility routines for the Bionic tool scripts

import commands
import logging
import os
import string
import sys


def panic(msg):
    sys.stderr.write(os.path.basename(sys.argv[0]) + ": error: ")
    sys.stderr.write(msg)
    sys.exit(1)


def get_kernel_headers_dir():
    return os.path.join(get_android_root(), "external/kernel-headers")


def get_kernel_headers_original_dir():
    return os.path.join(get_kernel_headers_dir(), "original")


def get_kernel_headers_modified_dir():
    return os.path.join(get_kernel_headers_dir(), "modified")


def get_kernel_dir():
    return os.path.join(get_android_root(), "bionic/libc/kernel")


def get_android_root():
    if "ANDROID_BUILD_TOP" in os.environ:
        # Verify that the current directory is in the root.
        # If not, then print an error.
        cwd = os.getcwd()
        root = os.environ["ANDROID_BUILD_TOP"]
        if len(cwd) < len(root) or not root == cwd[:len(root)]:
            panic("Not in android tree pointed at by ANDROID_BUILD_TOP (%s)\n" % root)
        return os.environ["ANDROID_BUILD_TOP"]
    panic("Unable to find root of tree, did you forget to lunch a target?\n")


class StringOutput:
    def __init__(self):
        self.line = ""

    def write(self,msg):
        self.line += msg
        logging.debug("write '%s'" % msg)

    def get(self):
        return self.line


def create_file_path(path):
    dirs = []
    while 1:
        parent = os.path.dirname(path)
        #print "parent: %s <- %s" % (parent, path)
        if parent == "/" or parent == "":
            break
        dirs.append(parent)
        path = parent

    dirs.reverse()
    for dir in dirs:
        #print "dir %s" % dir
        if os.path.isdir(dir):
            continue
        os.mkdir(dir)


class BatchFileUpdater:
    """a class used to edit several files at once"""
    def __init__(self):
        self.old_files = set()
        self.new_files = set()
        self.new_data  = {}

    def readFile(self,path):
        #path = os.path.realpath(path)
        if os.path.exists(path):
            self.old_files.add(path)

    def readDir(self,path):
        #path = os.path.realpath(path)
        for root, dirs, files in os.walk(path):
            for f in files:
                dst = "%s/%s" % (root,f)
                self.old_files.add(dst)

    def editFile(self,dst,data):
        """edit a destination file. if the file is not mapped from a source,
           it will be added. return 0 if the file content wasn't changed,
           1 if it was edited, or 2 if the file is new"""
        #dst = os.path.realpath(dst)
        result = 1
        if os.path.exists(dst):
            f = open(dst, "r")
            olddata = f.read()
            f.close()
            if olddata == data:
                self.old_files.remove(dst)
                return 0
        else:
            result = 2

        self.new_data[dst] = data
        self.new_files.add(dst)
        return result

    def getChanges(self):
        """determine changes, returns (adds, deletes, edits)"""
        adds    = set()
        edits   = set()
        deletes = set()

        for dst in self.new_files:
            if not (dst in self.old_files):
                adds.add(dst)
            else:
                edits.add(dst)

        for dst in self.old_files:
            if not dst in self.new_files:
                deletes.add(dst)

        return (adds, deletes, edits)

    def _writeFile(self,dst):
        if not os.path.exists(os.path.dirname(dst)):
            create_file_path(dst)
        f = open(dst, "w")
        f.write(self.new_data[dst])
        f.close()

    def updateFiles(self):
        adds, deletes, edits = self.getChanges()

        for dst in sorted(adds):
            self._writeFile(dst)

        for dst in sorted(edits):
            self._writeFile(dst)

        for dst in sorted(deletes):
            os.remove(dst)

    def updateGitFiles(self):
        adds, deletes, edits = self.getChanges()

        if adds:
            for dst in sorted(adds):
                self._writeFile(dst)
            commands.getoutput("git add " + " ".join(adds))

        if deletes:
            commands.getoutput("git rm " + " ".join(deletes))

        if edits:
            for dst in sorted(edits):
                self._writeFile(dst)
            commands.getoutput("git add " + " ".join(edits))
