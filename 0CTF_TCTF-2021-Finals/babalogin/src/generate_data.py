#!/usr/bin/env python3

import sys

if len(sys.argv) <= 1:
    exit(1)

def readfilebytes(filename):
    with open(filename, "rb") as f:
        content = f.read()
    return content

def writefilestr(filename, content):
    with open(filename, "w") as f:
        f.write(content)

def bytes_to_c_array_code(b):
    return f"{{{','.join(map(hex, b))}}}"

templatefilenames = []
inputfilenames = []

formatdict = {}

for s in sys.argv[1:]:
    if s.endswith(".template"):
        templatefilenames.append(s)
    else:
        inputfilenames.append(s)


for filename in inputfilenames:
    content = readfilebytes(filename)
    contentvarname = filename.replace(".", "_")
    lengthvarname = contentvarname+"_len"

    formatdict[contentvarname] = bytes_to_c_array_code(content)
    formatdict[lengthvarname] = len(content)


for templatefilename in templatefilenames:
    outputfilename = templatefilename[:-len(".template")]
    rawcontent = readfilebytes(templatefilename).decode()
    finalcontent = rawcontent.format(**formatdict)
    writefilestr(outputfilename, finalcontent)

