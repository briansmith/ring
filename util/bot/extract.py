# Copyright (c) 2015, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Extracts archives."""


import os
import os.path
import tarfile
import shutil
import sys
import zipfile


def FixPath(output, path):
  """
  FixPath removes the first directory from path and returns the it and the
  concatenation of output and the remainder. It does sanity checks to ensure
  the resulting path is under output, but shouldn't be used on untrusted input.
  """
  # Even on Windows, zip files must always use forward slashes.
  if '\\' in path or path.startswith('/'):
    raise ValueError(path)

  first, rest = path.split('/', 1)
  rest = os.path.normpath(rest)
  if os.path.isabs(rest) or rest.startswith('.'):
    raise ValueError(rest)
  return first, os.path.join(output, rest)


def IterateZip(path):
  """
  IterateZip opens the zip file at path and returns a generator of
  (filename, mode, fileobj) tuples for each file in it.
  """
  with zipfile.ZipFile(path, 'r') as zip_file:
    for info in zip_file.infolist():
      yield (info.filename, None, zip_file.open(info))


def IterateTar(path):
  """
  IterateTar opens the tar.gz file at path and returns a generator of
  (filename, mode, fileobj) tuples for each file in it.
  """
  with tarfile.open(path, 'r:gz') as tar_file:
    for info in tar_file:
      if info.isdir():
        continue
      if not info.isfile():
        raise ValueError('Unknown entry type "%s"' % (info.name, ))
      yield (info.name, info.mode, tar_file.extractfile(info))


def main(args):
  if len(args) != 3:
    print >> sys.stderr, 'Usage: %s ARCHIVE OUTPUT' % (args[0],)
    return 1

  _, archive, output = args

  if not os.path.exists(archive):
    # Skip archives that weren't downloaded.
    return 0

  if archive.endswith('.zip'):
    entries = IterateZip(archive)
  elif archive.endswith('.tar.gz'):
    entries = IterateTar(archive)
  else:
    raise ValueError(archive)

  try:
    if os.path.exists(output):
      print "Removing %s" % (output, )
      shutil.rmtree(output)

    print "Extracting %s to %s" % (archive, output)
    prefix = None
    for path, mode, inp in entries:
      # Pivot the path onto the output directory.
      new_prefix, fixed_path = FixPath(output, path)

      # Ensure the archive is consistent.
      if prefix is None:
        prefix = new_prefix
      if prefix != new_prefix:
        raise ValueError((prefix, new_prefix))

      # Extract the file.
      if not os.path.isdir(os.path.dirname(fixed_path)):
        os.makedirs(os.path.dirname(fixed_path))
      with open(fixed_path, 'w') as out:
        out.write(inp.read())

      # Fix up permissions if needbe.
      # TODO(davidben): To be extra tidy, this should only track the execute bit
      # as in git.
      if mode is not None:
        os.chmod(fixed_path, mode)
  finally:
    entries.close()

  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))
