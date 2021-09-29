#!/usr/bin/env python3

import sys,re
import getopt
from glob import glob
import sqlite3
import os
import shutil
import time
import tempfile
import subprocess

import pprint

from datasketch import MinHash, LeanMinHash
import itertools

from run import tokenize

MINHASH_PERMS = 64
THRESHOLD = 0.5
VERBOSE = False

start = time.time()


'''
<number:set_of_filename:funcname>

'''
minhashdb = {}

def debug(*args, **kwargs):
	if VERBOSE:
		print(*args,file=sys.stderr, **kwargs)

def elog(*args, **kwargs):
	print(*args,file=sys.stderr, **kwargs)

def usage():
	print("usage:\n%s <path to binary or .ll file>"%sys.argv[0] )
	# print("action can include extract, tokenize, minhash, ssdeep, ssdeep_ll, simhash, simhash_ft compare, compare_ll, confusion_matrix")
	print('''
		arguments:
		-f funcion_name		: function name(s) to evaluate during compare (comma separated)
		-p permutations		: number of permutations for minhash, or tolerance k for simhash
		-d path/to/data		: path to data directory)
		-t threshold		: threshold for matching in minhash and simhash (e.g 0.5 for minhash, 10 for simhash)
		-v		: verbose debugging messages

		''')


def extract_functions_retdecLL(filepath):
	'''
	extract functions from retdec LLVM IR

	return a dictionary of funcname:funccode?
	'''

	# function regex for llvm ir from retdec
	func_re = r'define .* (@.*){\n'
	pattern = re.compile(func_re)

	with open(filepath) as f:
		data = f.read()
		debug(f"[extract_functions_retdecLL] done reading {filepath} into mem..")

	res = {}
	r = pattern.search(data)
	prev = None
	count = 0
	skipCount = 0

	# the goal is to dump out the entire block, by reading from end of last label match to start of current match

	while r:
		
		# print the match
		# print(r.group())
		# read until end of function (marked by '}')
		funcEnd = data[r.start():].find('}')
		# debug(f"start: {r.start()} funcEnd:{funcEnd}")
		funcCode = data[r.start():r.start() + funcEnd] + '}'
		fheader = funcCode.split('{')[0]
		fname = fheader.split('(')[0].split(' ')[-1]

		if res.get(fname) != None:
			print(f"duplicate function f{fname}")

		res[fname] = funcCode


		r = pattern.search(data, r.start() + 1)

		count += 1

	if skipCount > 0:
		debug(f"skipped {skipCount} functions")

	return res

def lift(binaryPath):
	# if this program from retdec is not in your path, use full path
	# install from https://github.com/avast/retdec
	retdecDecompilerPath = "retdec-decompiler"

	# make temp directory and copy file over
	tmpd = tempfile.mkdtemp(prefix="tmp-"+os.path.basename(binaryPath), dir='./temp')
	newbin = shutil.copy(binaryPath, tmpd)
	# decompile
	os.system(f"{retdecDecompilerPath} {newbin}")

	# remove copied bin
	os.remove(newbin)
	
	llFile = f"{newbin}.ll"
	if not os.path.exists(llFile):
		print("error - lifted LL file not found")
		exit(2)
		# import code
		# code.interact(local=locals())
		# exit(1)
	return llFile




def lookupBinary(path):
	'''
	decompile a binary, calculate hashes for each function and then look it up in the database

	'''
	# lift binary using retdec
	if path.endswith('.ll'):
		llpath = path
	else:
		llpath = lift(path)
	functions = extract_functions_retdecLL(llpath)
	# os.remove(llpath)
	lstart = time.time()

	# schema: funcname:[(filefunc, match_score)]
	matches = {}


	# get the minhash values of each
	for fname in functions:
		functokens = tokenize(functions[fname])
		# using LeanMinHash because the pipeline does, to be consistent
		m = MinHash(num_perm=MINHASH_PERMS)

		for t in functokens:
			m.update(t.encode('utf8'))
			# m.update(t)

		lm = LeanMinHash(m)
		hashvals = lm.hashvalues

		# print(f'{fname}:{hashvals}')
		# for each function, find all similar functions in the db (each function would be O(64) for 64 hash lookups)
		# funcname: hash match
		hashcounts = {}
		for h in hashvals:
			if minhashdb.get(h) == None: # no match
				continue
			for filefunc in minhashdb.get(h):
				if hashcounts.get(filefunc) == None:
					hashcounts[filefunc] = 0
				hashcounts[filefunc] += 1


		for filefunc in hashcounts:
			score = hashcounts[filefunc] / MINHASH_PERMS
			if score >= THRESHOLD:
				if matches.get(fname) == None:
					matches[fname] = []
				matches[fname].append((filefunc, score))
	pprint.pprint(matches, indent=2)

	print("lookupBinary took", (time.time() - lstart))




DATADIR = 'data' # in the current dir

OUTPUT_DBPATHS = {'extract':'ll_extract.db', 'tokenize':'tokens.db', 'hash':'hashes.db'}

MINHASH_PERMS = 64

# main 


funcNames = None

opts, args = getopt.gnu_getopt(sys.argv[1:], 'hvd:a:t:p:f:')
for tup in opts:
	o,a = tup[0], tup[1]
	if o == '-h':
		usage()
		exit(0)
	elif o == '-d':
		DATADIR = a
	elif o == '-p':
		MINHASH_PERMS = int(a)
	elif o == '-f':
		funcNames = a
	# elif o == '-a':
	# 	ALGO = a
	elif o == '-v':
		VERBOSE = True
	elif o == '-t':
		THRESHOLD = float(a)

if len(args) < 1:
	print('missing path to file.')
	usage()
	exit(1)
targetpath = args[0]

# connect to db
dbpath = os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash'])
con = sqlite3.connect(dbpath)
cur = con.cursor()

allfilefuncs = set()

rows = cur.execute("SELECT filename,fname,hashvals FROM funcminhash WHERE numperms=?", (MINHASH_PERMS,))
for r in rows:
	filename = r[0]
	fname = r[1]
	fname_filename = filename + ":" + fname
	allfilefuncs.add(fname_filename)
	hashvalStr = r[2]
	# hashvals = [ int(i) for i in hashvalStr.split(',') ]
	for i in hashvalStr.split(','):
		i = int(i)
		if minhashdb.get(i) == None:
			minhashdb[i] = set()

		minhashdb[i].add(fname_filename)

	# print(f"{filename}:{fname}")
	
print(f"finished storing minhashdb, elapsed {time.time() - start}")
print(f"{len(allfilefuncs)} filename:funcname total")

lookupBinary(targetpath)
print("elapsed:", time.time() - start)
#import code
#code.interact(local=locals())

