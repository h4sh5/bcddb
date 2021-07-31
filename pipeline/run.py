#!/usr/bin/env python3

import sys,re
import getopt
from glob import glob
import sqlite3
import os
import time

from datasketch import MinHash, LeanMinHash
import itertools
# import murmurhash
# import mmh3

import statistics


VERBOSE = False # can be turned off via flags

def debug(*args, **kwargs):
	if VERBOSE:
		print(*args,file=sys.stderr, **kwargs)

def elog(*args, **kwargs):
	print(*args,file=sys.stderr, **kwargs)


# TODO: search action, for comparing a function against ALL hashes in DB

def usage():
	print("usage:\n%s <action>"%sys.argv[0] )
	print("action can include extract, tokenize, hash, compare")
	print('''
		arguments:
		-f funcion_name		: function name(s) to evaluate during compare (comma separated)
		-p permutations		: number of permutations for minhash

		''')

DATADIR = 'data' # in the current dir

OUTPUT_DBPATHS = {'extract':'ll_extract.db', 'tokenize':'tokens.db', 'hash':'hashes.db'}

MINHASH_PERMS = 64 # default setting is 128, but can shrink due to small length of instructions

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
		result_tokens.append(";")
		debug(result_tokens)
		return result_tokens # signify end of instruction
	return None


def mmh(d):
    return murmurhash.hash(d)


############################ main

if len(sys.argv) < 2:
	usage()
	exit(1)

funcNames = None

opts, args = getopt.gnu_getopt(sys.argv[1:], 'hd:p:f:')
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
		elif o == '-v':
			VERBOSE = True


action = args[0]

start = time.time()

if "extract" in action:

	# create db
	dbpath = os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract'])
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


# TODO decouple token and hash? or later?
if "tokenize" in action:
	indbpath = os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract'])
	con = sqlite3.connect(indbpath)
	cur = con.cursor()
	# XXX take one for example
	rows = cur.execute("SELECT filename, fname, llcode FROM function ORDER BY RANDOM()")

	fnhashCount = 0
	fnSkipCount = 0

	for row in rows:
	
		filename = row[0]
		fname = row[1]
		# print(f"function: {filename}{fname}")
		llcode = row[2]
		functokens = []

		for line in llcode.split("\n"):
			# each line is an LLVM IR instruction
			# skip labels
			line = line.lstrip() # strip leading whitespace
			if line.startswith('dec_label') or line == '}' or line.startswith('define'):
				continue
			tokens = tokenize(line)

			if tokens:		
				# print(tokens) # each instruction
				functokens.extend(tokens)

		if "hash" in action:

			'''
			# minhashes can be computed in bulk!
			# takes bytes, so need encoding!
			data = [[b'token1', b'token2', b'token3'],
				  [b'token4', b'token5', b'token6']]
			minhashes = MinHash.bulk(data, num_perm=64)
			'''
			con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
			cur = con.cursor()
			# TODO: create single hash number table to store each value individually 
			# for more scalable comparison
			cur.execute('''
				CREATE TABLE IF NOT EXISTS funchash (filename VARCHAR, fname VARCHAR, 
									numperms INT, hashvals VARCHAR, PRIMARY KEY (filename, fname, numperms))''')
			con.commit()
			if functokens:

				# can also use LeanMinHash to save memory/space!
				 #, hashfunc=mmh3.hash)
				m = MinHash(num_perm=MINHASH_PERMS)

				for t in functokens:
					m.update(t.encode('utf8'))
					# m.update(t)

				lm = LeanMinHash(m)
				hashvals = str(list(lm.hashvalues)).lstrip('[').rstrip(']')
				# debug('hash:', hashvals)
				try:
					cur.execute("INSERT INTO funchash (filename,fname, numperms, hashvals) values(?,?,?,?)",
						(
							filename, 
							fname, 
							MINHASH_PERMS, 
							hashvals
						)
					)
					con.commit()
					fnhashCount += 1
				
				except sqlite3.IntegrityError:
					fnSkipCount += 1
					pass
				
				# import code
				# code.interact(local=locals())

if "compare" in action:
	con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
	cur = con.cursor()
	
	if funcNames == None:
		print("please specify function name(s) to compare in -f ")
		exit(1)

	# if len(funcNames.split(',')) > 1:
		# TODO implement cross-function comparison

		# mapping < CONCAT(funcname,filename) : hashobjs>
	funcnameFilename_hashobjs = {}
	jaccard_dists = []

	# print CSV header
	print('filefunc0,filefunc1,permutations,jaccard_dist')

	for funcName in funcNames.split(','):
		rows = cur.execute("SELECT filename,fname,hashvals FROM funchash WHERE fname LIKE ? AND numperms=?", (funcName, MINHASH_PERMS))
		for r in rows:
			filename = r[0]
			fname = r[1]
			fname_filename = filename + ":" + fname
			hashvalStr = r[2]
			hashvals = [ int(i) for i in hashvalStr.split(',') ]
			# print(f"{filename}:{fname}")
			funcnameFilename_hashobjs[fname_filename] = MinHash(hashvalues=hashvals)
	# print(funcnameFilename_hashobjs)
	for p in itertools.combinations(funcnameFilename_hashobjs.keys(), 2):
		filefunc0 = p[0]
		filefunc1 = p[1]
		m0 = funcnameFilename_hashobjs[filefunc0]
		m1 = funcnameFilename_hashobjs[filefunc1]
		jaccardi = m0.jaccard(m1)
		jaccard_dists.append(jaccardi)

		print(f"{filefunc0},{filefunc1},{MINHASH_PERMS},{jaccardi}")

	# average jacard distance will show how well comparisons worked for this function across different architectures.
	if len(jaccard_dists) > 0:
		elog(f"min jaccard dist: {min(jaccard_dists)}")
		elog(f"max jaccard dist: {max(jaccard_dists)}")
		elog(f"median jaccard dist: {statistics.median(jaccard_dists)}")
		elog(f"mean jaccard dist: {statistics.mean(jaccard_dists)}")


elog(f"done, elapsed {time.time() - start} seconds")
