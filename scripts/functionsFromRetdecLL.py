#!/usr/bin/env python3

import re, sys

if len(sys.argv) < 2:
	print("usage:\n%s <file>"%sys.argv[0] )
	exit(1)


def elog(s, **kwargs):
	print(s, **kwargs, file=sys.stderr)

# function regex for llvm ir from retdec
func_re = r'define .* (@.*){\n'
pattern = re.compile(func_re)

with open(sys.argv[1]) as f:
	elog("reading the entire file into mem..")
	data = f.read()

r = pattern.search(data)
prev = None

h = '-'*40

# the goal is to dump out the entire block, by reading from end of last label match to start of current match

while r:
	
	# print the match
	print(r.group())
	# read until end of function (marked by '}')
	funcEnd = data[r.start():].find('}')
	print(f"start: {r.start()} funcEnd:{funcEnd}")
	funcCode = data[r.start():r.start() + funcEnd] + '}'

	print(funcCode + '\n' + h)
	# console
	# import code
	# code.interact(local=locals())

	r = pattern.search(data, r.start() + 1)
	




