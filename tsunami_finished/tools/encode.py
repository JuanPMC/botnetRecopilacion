import base64
import sys

if len(sys.argv) != 2:
    sys.exit("Usage: python2 %s [string]" % (sys.argv[0]))
encoded = base64.b64encode(sys.argv[1])
l = list(encoded)
swap = 2
l[::swap], l[1::swap] = l[1::swap], l[::swap]
str = "".join(l)
out = str.replace("=", "A")
print "Output: %s:%d" % (out, len(out))
