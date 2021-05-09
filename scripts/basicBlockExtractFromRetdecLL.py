#!/usr/bin/env python3

import re, sys

if len(sys.argv) < 2:
	print("usage:\n%s <file>"%sys.argv[0] )
	exit(1)


def elog(s, **kwargs):
	print(s, **kwargs, file=sys.stderr)

# for llvm ir only
label_re = r'dec_label_.*'
pattern = re.compile(label_re)

with open(sys.argv[1]) as f:
	elog("reading the entire file into mem..")
	data = f.read()

r = pattern.search(data)
prev = None

h = '-'*40

# the goal is to dump out the entire block, by reading from end of last label match to start of current match

while r:
	
	r = pattern.search(data, r.start() + 1)
	# print the match


	if prev and r:
		print(h)
		print("%d,%d" % (prev.start(), prev.end()))
		print(prev.group())
		
		print(data[prev.end():r.start()])
		print('/'+h)
	else:
		elog('end of search.')

	prev = r
	# console
	# import code
	# code.interact(local=locals())




