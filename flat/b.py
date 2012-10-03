import sys
import re
lines = open(sys.argv[1], 'rb').readlines()

def _consume_docstrings(lines):
    while lines:
        line = lines.pop(0)
        #print 'CONSUME', repr(line)
        if line.strip().endswith('"""'):
            break

def consume_docstrings(lines):
    newlines = []
    while lines:
        line = lines[0]
        if line.strip().startswith('"""') or line.strip().startswith('r"""'):
            _consume_docstrings(lines)
        elif line.startswith('#'):
            lines.pop(0)
        elif re.match('^ +#.*$', line):
            lines.pop(0)
        else:
            line = lines.pop(0)
            newlines.append(line)
            #print line,
    return newlines

def register_imports(lines):
    newlines = []
    while lines:
        line = lines[0]
        if (line.startswith('from tornado') or
                line.startswith('import tornado')):
            line = lines.pop(0)
        else:
            line = lines.pop(0)
            newlines.append(line)
    return newlines

lines = consume_docstrings(lines)
lines = register_imports(lines)
for line in lines:
    print line,
