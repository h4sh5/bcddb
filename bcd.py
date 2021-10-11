#!/usr/bin/env python3

import sys,re
import getopt
from glob import glob
import os
import shutil
import time
import tempfile
import subprocess

import pprint

import pickle
from datasketch import MinHash, LeanMinHash
import itertools


start = time.time()

'''
schema of dictionary db:
<hash:List[filename_funcname,..]>

'''
MINHASHDB = {}

def debug(*args, **kwargs):
	if VERBOSE:
		print(*args,file=sys.stderr, **kwargs)

def elog(*args, **kwargs):
	print(*args,file=sys.stderr, **kwargs)

def usage():
	print("usage:\n%s <-i/-s> [options] <path to binary or .ll files> .."%sys.argv[0] )
	# print("action can include extract, tokenize, minhash, ssdeep, ssdeep_ll, simhash, simhash_ft compare, compare_ll, confusion_matrix")
	print('''
		arguments:
		-s		: search mode, lookup similar functions
		-i		: index mode, indexes binaries/ll files into db pickle
		-f path_to_pickle		: path to pickle file of bcd
		-p permutations		: number of permutations for minhash
		-t threshold		: threshold for matching in minhash and simhash (e.g 0.5 for minhash, 10 for simhash)
		-v		: verbose debugging messages

		''')

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
				debug(f'replacing {t} with {s}')
				result_tokens.append(s)
				replaced = True
				break
		if replaced:
			continue

		elif t[:3] in intsizes:
			debug(f'dropping {t}')
			continue


		elif t.startswith('%') and not ("(" in t):
			# generic variable reference
			newt = '%r'
			debug(f'replacing {t} with {newt}')
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
		#result_tokens.append(";")
		debug(result_tokens)
		return result_tokens # signify end of instruction
	return None

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
	tmpd = tempfile.mkdtemp(prefix="tmp-"+os.path.basename(binaryPath)+'_', dir='./temp')
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




def lookupPath(path):
	'''
	decompile a binary (or all binaries in a directory), calculate hashes for each function and then look it up in the database

	'''

	if os.path.isdir(path):
		dirpath = path
		for i in os.walk(dirpath):
			files = i[2]
			for file in files:
				filepath = os.path.join(dirpath, file)
				# print(path)
				lookupPath(filepath)
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
			if MINHASHDB.get(h) == None: # no match
				continue
			for filefunc in MINHASHDB.get(h):
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

	print("lookupPath took", (time.time() - lstart))

	return matches



def indexPath(path):
	'''
	decompile a binary (or all binaries in a directory), calculate hashes for each function and then store it in the database
	'''
	global MINHASHDB

	if os.path.isdir(path):
		dirpath = path
		for i in os.walk(dirpath):
			files = i[2]
			for file in files:
				filepath = os.path.join(dirpath, file)
				# print(path)
				indexPath(filepath)
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
		filename_funcname = os.path.basename(path) + ":" + fname
		for h in hashvals:
			if MINHASHDB.get(h) == None:
				MINHASHDB[h] = set()
			# if filename_funcname not in MINHASHDB[h]
			elif type(MINHASHDB.get(h)) == list:
				# convert entry to set if its a list (old version)
				MINHASHDB[h] = set(MINHASHDB[h])
			MINHASHDB[h].add(filename_funcname)


	print("indexPath took", (time.time() - lstart))




MINHASH_PERMS = 64
THRESHOLD = 0.5
VERBOSE = False

PICKLEFILE = 'db_dict.pkl'

# OUTPUT_DBPATHS = {'extract':'ll_extract.db', 'tokenize':'tokens.db', 'hash':'hashes.db'}

MINHASH_PERMS = 64

MODE = 'lookup'

# main
if __name__ == '__main__':
	funcNames = None

	opts, args = getopt.gnu_getopt(sys.argv[1:], 'hvisd:a:t:p:f:')
	for tup in opts:
		o,a = tup[0], tup[1]
		if o == '-h':
			usage()
			exit(0)
		elif o == '-i':
			MODE = 'index'
		elif o == '-s':
			MODE = 'lookup'
		elif o == '-f':
			PICKLEFILE = a
		elif o == '-p':
			MINHASH_PERMS = int(a)
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

	allfilefuncs = set()


	if not os.path.exists(PICKLEFILE):
		MINHASHDB = {}
	else:
		with open(PICKLEFILE,'rb') as f:
			MINHASHDB = pickle.load(f)
			print(f"finished loading db dictionary, elapsed {time.time() - start}")
			print(f"hashes in db: {len(MINHASHDB)}")

	for targetpath in args:

		if MODE == 'lookup':
			if not os.path.exists(PICKLEFILE):
				print("no db pickle file specified, can't do lookup")
				exit(1)
			lookupPath(targetpath)
		elif MODE == 'index':
			indexPath(targetpath)
			print(f"hashes in db after indexing: {len(MINHASHDB)}")
			with open(PICKLEFILE,'wb') as f:
				pickle.dump(MINHASHDB, f)
			print(f"updated db at {PICKLEFILE}")

	print("elapsed:", time.time() - start)
	#import code
	#code.interact(local=locals())

