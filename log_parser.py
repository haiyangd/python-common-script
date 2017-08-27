from datetime import datetime
import re
from sys import argv, exit
"USAGE: %s logname expect_string"

CURRENT_YEAR = datetime.now().year
if len(argv) != 3:
    print __doc__ , argv[0]
    exit(0)


class Parser(object):
    def __init__(self, file_path, regexp):
        self.file_path = file_path
        self.regexp = regexp

    def parse(self):
        # Infinite seeking, reproduce tail -f behavior by using a generator
        if not hasattr(self, '_pos'):
            self._pos = None
        with open(self.file_path, 'r') as fp:
            if self._pos is None:
                # Seek to end of file and store position
                fp.seek(0, 2)
                self._pos = fp.tell()
            else:
                # Seek to the last known position
                fp.seek(self._pos, 0)
                for line in fp:
                    if line != "\n" and not self.check_line(line):
                        yield line
                self._pos = fp.tell()

    def parse_datetime(self, line):
        raise NotImplementedError

    def check_line(self, line):
        raise NotImplementedError


class LogParser(Parser):
    def check_line(self, line):
        if re.findall(self.regexp, line):
            return False
        else:
            return True
#print argv[2]
parser = LogParser(file_path=argv[1], regexp=argv[2])
while True:
    for line in parser.parse():
        print line
        if argv[2] in line:
           exit (0)
#parser.parse()
