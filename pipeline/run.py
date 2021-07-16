#!/usr/bin/env python3

import sys,re
import getopt
from glob import glob
import sqlite3
import os
import time

DEBUG = True # can be turned off via flags

def debug(*args, **kwargs):
	if DEBUG:
		print(*args,file=sys.stderr, **kwargs)

def help():
	print("usage:\n%s <stage>"%sys.argv[0] )
	print("stage can be extract, tokenize, hash, compare")

DATADIR = 'data' # in the current dir

OUTPUT_DBPATHS = {'extract':'ll_extract.db', 'tokenize':'tokens.db', 'hash':'hashes.db'}



def extract_functions_retdecLL(filepath, sqlite_con = None) -> int:
	'''
	extract functions from retdec LLVM IR, optionally commit to sqlite3 db, 
	skip duplicates, and return count
	'''

	# function regex for llvm ir from retdec
	func_re = r'define .* (@.*){\n'
	pattern = re.compile(func_re)

	with open(filepath) as f:
		data = f.read()
		debug(f"[extract_functions_retdecLL] done reading {filepath} into mem..")


	r = pattern.search(data)
	prev = None
	count = 0
	skipCount = 0

	# the goal is to dump out the entire block, by reading from end of last label match to start of current match

	if sqlite_con != None:
		cur = sqlite_con.cursor()
	while r:
		
		# print the match
		# print(r.group())
		# read until end of function (marked by '}')
		funcEnd = data[r.start():].find('}')
		# debug(f"start: {r.start()} funcEnd:{funcEnd}")
		funcCode = data[r.start():r.start() + funcEnd] + '}'
		fheader = funcCode.split('{')[0]
		fname = fheader.split('(')[0].split(' ')[-1]

		# debug(f" fname: {fname}| fheader: {fheader}")#,funcCode + '\n' + '-'*40)

		if sqlite_con != None:
			try:
				cur.execute("INSERT INTO function(filename, fname, fheader, llcode, startpos, endpos) \
						values(?,?,?,?,?,?)", (os.path.basename(filepath), fname, fheader, funcCode, r.start(), funcEnd))
				sqlite_con.commit()
			except sqlite3.IntegrityError: # already exists
				skipCount += 1
				pass
		
		# console
		# import code
		# code.interact(local=locals())

		r = pattern.search(data, r.start() + 1)

		count += 1

	if skipCount > 0:
		debug(f"skipped {skipCount} functions")
	return count

def extract_BB_retdecLL(filepath, sqlite_con = None) -> int:
	'''
	extract basic blocks from retdec LLVM IR, optionally commit to sqlite3 db, 
	skip duplicates, and return count
	'''

	label_re = r'dec_label_.*'
	pattern = re.compile(label_re)
	count = 0
	skipCount = 0

	with open(filepath) as f:
		data = f.read()
		debug(f"[extract_BB_retdecLL] done reading {filepath} into mem..")

	r = pattern.search(data)
	prev = None

	while r:
		
		r = pattern.search(data, r.start() + 1)
		if prev and r:
			# print(h)
			# print("%d,%d" % (prev.start(), prev.end()))
			# debug(prev.group())
			label = prev.group()#split(':')[0].split(',')[0]
			code = data[prev.end():r.start()] 
			# debug(label)
			# debug(bbcode)

			if sqlite_con != None:
				try:
					cur.execute("INSERT INTO basicblock(filename, label, llcode, startpos, endpos) \
						values(?,?,?,?,?)", (os.path.basename(filepath), label, code, prev.end(), r.start()))
					sqlite_con.commit()
				except sqlite3.IntegrityError: # already exists
					skipCount += 1
					pass

			count += 1
			# print('/'+h)
		# else:
		# 	elog('end of search.')
		prev = r

	if skipCount > 0:
		debug(f"skipped {skipCount} basic blocks")

	return count


def tokenize(instruction):
	'''
	takes an llvm IR instruction and returns a list of string tokens
	'''
	tokens = instruction.split()
	result_tokens = []

	intsizes = ['i4', 'i8', 'i16', 'i32', 'i64',
		'u4', 'u8', 'u16', 'u32', 'u64']

	# when a token starts with a shoterner, truncate it to the shortener.
	shorteners = ['%stack_var', '%dec_label', '%global', '@global']

	for i in range(len(tokens)):
		# run replacement rules
		t = tokens[i]
		replaced = False

		
		for s in shorteners:
			if t.startswith(s):
				# debug(f'replacing {t} with {s}')
				result_tokens.append(s)
				replaced = True
				break
		if replaced:
			continue

		elif t[:3] in intsizes:
			# debug(f'dropping {t}')
			continue


		elif t.startswith('%') and not ("(" in t):
			# generic variable reference
			newt = '%r'
			# debug(f'replacing {t} with {newt}')
			result_tokens.append(newt)

		elif t == '!insn.addr': # stop processing
			break

		
		else:
			newt = t
			for it in intsizes:
				newt = newt.replace(it, '')
			# newt = t.replace()
			result_tokens.append(newt)


		# can use lookahead to determine nature of token
	if result_tokens != []:
		result_tokens.append(";")
		return result_tokens # signify end of instruction
	return None





############################ main

if len(sys.argv) < 2:
	help()
	exit(1)


opts, args = getopt.gnu_getopt(sys.argv[1:], 'hd:')
for tup in opts:
        o,a = tup[0], tup[1]
        if o == '-h':
            usage()
            exit(0)
        elif o == '-d':
        	datadir = a

stage = args[0]

start = time.time()

if stage == "extract":

	# create db
	dbpath = os.path.join(DATADIR,"db",OUTPUT_DBPATHS[stage])
	con = sqlite3.connect(dbpath)
	cur = con.cursor()
	cur.execute('''CREATE TABLE IF NOT EXISTS function (filename VARCHAR, fname VARCHAR, 
								fheader VARCHAR, llcode VARCHAR, ccode VARCHAR, startpos INT, endpos INT,
								PRIMARY KEY(filename, fheader))''')
	cur.execute('''CREATE TABLE IF NOT EXISTS basicblock (filename VARCHAR, label VARCHAR, 
								llcode VARCHAR, startpos INT, endpos INT, 
								PRIMARY KEY(filename, label))''')
	con.commit()
	
	globexp = DATADIR+"/ll"+"/*.ll"
	fcount = 0
	bbcount = 0
	# debug(globexp)
	for file in glob(globexp):
		fcount += extract_functions_retdecLL(file, sqlite_con=con)
		bbcount += extract_BB_retdecLL(file, sqlite_con=con)



	print(f"extract done, elapsed {time.time() - start}")
	print(f"extracted {fcount} funcs in total")
	print(f"extracted {bbcount} basic blocks in total")
	print(f"find the results in {dbpath}")



if stage == "tokenize":
	indbpath = os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract'])
	con = sqlite3.connect(indbpath)
	cur = con.cursor()
	# XXX take one for example
	cur.execute("SELECT filename, fname, llcode FROM function ORDER BY RANDOM() LIMIT 1")
	row = cur.fetchone()
	print(f"function: {row[0]}{row[1]}")
	llcode = row[2]
	for line in llcode.split("\n"):
		# each line is an LLVM IR instruction
		# skip labels
		line = line.lstrip() # strip leading whitespace
		if line.startswith('dec_label') or line == '}' or line.startswith('define'):
			continue
		tokens = tokenize(line)
		
		print(tokens)
