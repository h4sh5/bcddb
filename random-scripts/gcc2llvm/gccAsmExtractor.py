#!/usr/bin/env python3

'''
this script reads in an assmebly listing compiled with gcc -S -g 
(debug symbols), and with any optional optimization levels (doesn matter)

and parse them into functions and basic blocks with corresponding debug symbols

multiple .S files can be analyzed at a time but assume that they are from the
same project (so that basic block labels can be sorted etc.)

'''

import sys
import re
from func import BasicBlock, Function

def elog(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)

if len(sys.argv) < 2:
	elog(f"usage: {sys.argv[0]} <files>")
	exit(1)

files = []

for fn in sys.argv[1:]:
	files.append(fn)

	
'''
example of gcc asm listing:

main:
.LVL31:
.LFB42:
	.loc 1 48 1 view -0
	.cfi_startproc
	.loc 1 48 1 is_stmt 0 view .LVU97
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24

anything with 'adsf:' is a function label (must follow C function naming guides,
as they correspond to the actual function names from the src code)

the rest of the labels:
#define FUNC_BEGIN_LABEL  "LFB"
#define FUNC_END_LABEL    "LFE"
#define BLOCK_BEGIN_LABEL "LBB"
#define BLOCK_END_LABEL   "LBE"
ASM_GENERATE_INTERNAL_LABEL (loclabel, "LVL", loclabel_num);

https://stackoverflow.com/questions/24787769/what-are-lfb-lbb-lbe-lvl-loc-in-the-compiler-generated-assembly-code

have to deal with multi file projects somehow, as .S files are individual while
binaries are compiled usually from multiple .c files

basic blocks can _overlap_ between functions ... (one function can start within
a previous basic block?)
'''


def getLocInfo(data: str, regex, labelMap: dict):
	'''
	search string data from gcc .S file using regex to match labels, and then
	read the loc info (start line) into labelMap

	TODO: might also need to store filename

	'''
	block = regex.search(data)
	print(block)

	# import code
	# code.interact(local=locals())

	while block:
		# print(block.groups()[0])
		label = block.groups()[0]
		# import code
		# code.interact(local=locals())

		# read in loc info
		locStart=data[block.start():].find('.loc')
		locEnd = data[block.start()+locStart:].find('\n')
		locString = data[block.start()+locStart:][:locEnd]
		# read in line for now, maybe column not needed
		fileNum = locString.split()[1]
		startLine = locString.split()[2]
		col = locString.split()[3]
		labelMap[label] = startLine
		print(f'{label}: start at file {fileNum} line {startLine}')
		# bbStartLines[labelName]
		# bbs.append(BasicBlock(labelName, ))
		block = regex.search(data, block.start() + 1)



# functions have to start with letters (not numbers), or _
funcRe = re.compile(r'\n([a-zA-Z_].*):')
# basic block labels start with .LFB
labelStartRe = re.compile(r'(\.LBB[0-9].*):')
labelEndRe = re.compile(r'(\.LBE[0-9].*):')

# this array stores sequential basic blocks per gcc .S file
bbs = []
# maps basic block names (inside gcc .S files) to start and end lines
bbStartLines = {}
bbEndLines = {}


funcStartLines = {}

for fn in files:
	with open(fn, 'r') as f:
		# for faster data processing, read entire content of file into mem
		data = f.read()

		# block = labelStartRe.search(data)
		# print(block)

		getLocInfo(data, labelStartRe, bbStartLines)
		print('bbStartLines:', bbStartLines)

		# end lines are NOT ACCURATE, not using it (they mark the end of the
		# labels but they dont come attached with proper loc data)
		# getLocInfo(data, labelEndRe, bbEndLines)
		# print('bbEndLines:', bbEndLines)
		getLocInfo(data, funcRe, funcStartLines)
		print('funcStartLines:', funcStartLines)



