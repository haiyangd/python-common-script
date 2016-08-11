"""
Automated Backup Script.
Mounts an encfs directory and rsyncs a series of files to that path.  Also
makes periodic snapshots of the encfs directory for reverting changes.
Configurable based on file located at $HOME/.backuprc.  Triggered by cron
commands, see example_crontab.txt for an example:
"""
import logging
import os
import subprocess
import sys

# Modify this is you would like to put the config file anywhere other than
# $HOME/.backuprc
BACKUP_RC = os.path.join(os.environ['HOME'], 'backuprc')
print os.environ['HOME']

class BackupConfig(object):
  def __init__(self, filename):
    assert os.path.exists(filename)
    self.FILEPATHS = []
    self.Process(filename)

  def Process(self, filename):
      # Config lines are one of:
      #   - "# Comment beginning with hash character"
      #   - "" <- empty line that is ignored
      #   - "KEY VALUE" pairs
      #   - "/directory/to/recursively/backup/" <- must end in "/"
      #   - "/directory/with_specific_file.to_backup"
    for line in open(filename).xreadlines():
      line = line.strip()
      # lines beginning with # are comments
      if not line or line[0] == '#': continue

      # Add the key value pairs to my own dictionary
      if ' ' in line:
        key, value = line.split(' ', 1)
        self.__dict__[key] = value
      else:
        self.FILEPATHS.append(line)

class ShellError(OSError):
  """Popen() returned non-0."""
  def __init__(self, command, cwd, returncode, stdout, stderr=None):
    OSError.__init__(self, command, cwd, returncode, stdout, stderr)
    self.command = command
    self.cwd = cwd
    self.returncode = returncode
    self.stdout = stdout
    self.stderr = stderr

  def PrintWithPrefix(self, to_print, prefix_len):
    out = ""
    for line in to_print.splitlines():
      out += (" " * prefix_len) + to_print
    return out

  def __str__(self):
    out = "Return Value: %d\n" % self.returncode
    if self.stdout:
      out += self.PrintWithPrefix("<Standard Out>", 2)
      out += self.PrintWithPrefix(self.stdout.read(), 4)
      out += self.PrintWithPrefix("</Standard Out>", 2)
    if self.stderr:
      out += self.PrintWithPrefix("<Standard Err>\n", 2)
      out += self.PrintWithPrefix(self.stderr, 4)
      out += self.PrintWithPrefix("</Standard Err>", 2)
    return out


def Shell(cmd, cwd=None):
  process = subprocess.Popen(cmd, cwd=cwd, shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
  if process.wait():
    stdout, stderr = process.communicate()
    raise ShellError(cmd, cwd, process.returncode, stdout, stderr)



try:
  Shell("pwd")
except ShellError as e:
  print e.returncode
  if e.returncode != 32:  # 32 indicates already mounted
    logging.exception("Pre Mount Failed")
    raise


cfg = BackupConfig(BACKUP_RC)
print cfg.LOG_FILE
