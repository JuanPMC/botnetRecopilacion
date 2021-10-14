# -*- coding: utf-8

import sys
import sys
import os
import re
import binascii

def insert_slashx(string, every=2):
    return '\\x'.join(string[i:i + every] for i in xrange(0, len(string), every))

def split_count(s, count):
     return [''.join(x) for x in zip(*[list(s[z::count]) for z in range(count)])]

hex = "\\x" + insert_slashx(binascii.hexlify(open(sys.argv[1]).read()))
#echo = "echo -en \'" + "\" >>dropper\necho -en \"".join(split_count(hex, (64 * 2))) + "\" >>dropper"
print hex
