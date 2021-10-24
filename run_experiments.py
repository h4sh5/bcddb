#!/usr/bin/env python3

import sys,re
import getopt
from glob import glob
import sqlite3
import os
import time

from datasketch import MinHash, LeanMinHash
import itertools
import ssdeep
from pysimhash import SimHash

import tlsh

import statistics


VERBOSE = False # can be turned off via flags
ALGO = "minhash"
THRESHOLD = None

def debug(*args, **kwargs):
	if VERBOSE:
		print(*args,file=sys.stderr, **kwargs)

def elog(*args, **kwargs):
	print(*args,file=sys.stderr, **kwargs)


# TODO: search action, for comparing a function against ALL hashes in DB

def usage():
	print("usage:\n%s <action>"%sys.argv[0] )
	print("action can include extract, tokenize, minhash, ssdeep, ssdeep_ll, simhash, tlsh, compare, compare_ll, confusion_matrix")
	print('''
		arguments:
		-f funcion_name		: function name(s) to evaluate during compare (comma separated)
		-a algorithm		: hash algorithm to use during comparison (minhash|ssdeep)
		-p permutations		: number of permutations for minhash, or tolerance k for simhash
		-d path/to/data		: path to data directory)
		-t threshold		: threshold for matching in minhash and simhash (e.g 0.5 for minhash, 10 for simhash)
		-v		: verbose debugging messages

		''')

DATADIR = 'data' # in the current dir

OUTPUT_DBPATHS = {'extract':'ll_extract.db', 'tokenize':'tokens.db', 'hash':'hashes.db'}

MINHASH_PERMS = 256

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
		#result_tokens.append(";")
		debug(result_tokens)
		return result_tokens # signify end of instruction
	return None

## for simhash
def get_features(s):
	# width adjustable
    width = 3
    s = s.lower()
    s = re.sub(r'[^\w]+', '', s)
    return [s[i:i + width] for i in range(max(len(s) - width + 1, 1))]


def print_confusion_matrix(name, tpos, fpos, tneg, fneg):
	tpr = tpos/(tpos+fneg) # true pos rate
	fnr = fneg/(tpos+fneg) # false neg rate
	fpr = fpos/(fpos+tneg)
	tnr = tneg/(fpos+tneg) 
	# using rates instead of numbers because of class imbalance
	accuracy = (tpr + tnr) / (tpr + tnr + fpr + fnr)
	# real numbers for prec and rec
	#precision = tpos / (tpos + fpos)
	#recall = tpos / (fpos + fneg)
	print('''
|{} confusion matrix|  match| no match|
|------------------------|-------------|---------|
|           same funcname|{:>8.3f} ({})|{:>9.3f} ({})|
|           diff funcname|{:>8.3f} ({})|{:>9.3f} ({:})|
			'''.format(name,
				tpr,tpos,
				fnr,fneg,
				fpr,fpos,
				tnr,tneg))
	print('accuracy:', accuracy)



############################ main

if __name__ == "__main__":

	if len(sys.argv) < 2:
		usage()
		exit(1)

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
			elif o == '-a':
				ALGO = a
			elif o == '-v':
				VERBOSE = True
			elif o == '-t':
				THRESHOLD = float(a)


	action = args[0]

	start = time.time()

	if "extract" == action:

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
			# bbcount += extract_BB_retdecLL(file, sqlite_con=con)



		print(f"extract done, elapsed {time.time() - start}")
		print(f"extracted {fcount} funcs in total")
		print(f"extracted {bbcount} basic blocks in total")
		print(f"find the results in {dbpath}")


	# TODO decouple token and hash? or later?
	if "tokenize" == action:
		indbpath = os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract'])
		con = sqlite3.connect(indbpath)
		cur = con.cursor()
		cur.execute('''CREATE TABLE IF NOT EXISTS token (filename VARCHAR, fname VARCHAR, tokens TEXT, PRIMARY KEY(filename, fname))''')
		con.commit()
		rows = cur.execute("SELECT filename, fname, llcode FROM function")

		for row in rows:
			# elog(row[0])
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
					# insert into DB
			debug(f"inserting for {filename}:{fname}")
			functokens = ' '.join(functokens)
			insert_cur = con.cursor()  # cant use the same cursor 
			try:
				insert_cur.execute("INSERT into token (filename, fname, tokens) values (?, ?, ?)", (filename, fname, functokens))
			except sqlite3.IntegrityError as e:
				# elog('IntegrityError:', e)
				pass
			con.commit()

	if "minhash" == action:
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
			CREATE TABLE IF NOT EXISTS funcminhash (filename VARCHAR, fname VARCHAR, 
								numperms INT, hashvals VARCHAR, PRIMARY KEY (filename, fname, numperms))''')
		con.commit()

		tokencon =  sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract']))
		tokencur = 	tokencon.cursor()


		fnhashCount = 0
		fnSkipCount = 0

		rows = tokencur.execute("SELECT filename, fname, tokens from token")
		for row in rows:
			filename = row[0]
			fname = row[1]
			functokens = row[2]

			# can also use LeanMinHash to save memory/space!
			 #, hashfunc=mmh3.hash)
			m = MinHash(num_perm=MINHASH_PERMS)

			for t in functokens.split():
				m.update(t.encode('utf8'))
				# m.update(t)

			lm = LeanMinHash(m)
			hashvals = str(list(lm.hashvalues)).lstrip('[').rstrip(']')
			# debug('hash:', hashvals)
			try:
				cur.execute("INSERT INTO funcminhash (filename,fname, numperms, hashvals) values(?,?,?,?)",
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
		elog(f"calculated {fnhashCount} hashes, skipped {fnSkipCount}")

	if "ssdeep" == action:
		con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
		cur = con.cursor()
		# TODO: create single hash number table to store each value individually 
		# for more scalable comparison
		cur.execute('''
			CREATE TABLE IF NOT EXISTS funcssdeep (filename VARCHAR, fname VARCHAR, 
							ssdeep VARCHAR, PRIMARY KEY (filename, fname))''')
		con.commit()

		tokencon =  sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract']))
		tokencur = 	tokencon.cursor()


		fnhashCount = 0
		fnSkipCount = 0

		rows = tokencur.execute("SELECT filename, fname, tokens from token")
		for row in rows:
			filename = row[0]
			fname = row[1]
			functokens = row[2]
			fhash = ssdeep.hash(functokens)
			debug(f'ssdeep of {filename}:{fname} ', fhash)
			try:
				cur.execute("INSERT INTO funcssdeep (filename,fname, ssdeep) values(?,?,?)",
					(
						filename, 
						fname,
						fhash
					)
				)
				con.commit()
				fnhashCount += 1
			
			except sqlite3.IntegrityError:
				fnSkipCount += 1
				pass
		elog(f"calculated {fnhashCount} hashes, skipped {fnSkipCount}")


	if "ssdeep_ll" == action:

		con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
		cur = con.cursor()
		# TODO: create single hash number table to store each value individually 
		# for more scalable comparison
		cur.execute('''
			CREATE TABLE IF NOT EXISTS funcll_ssdeep (filename VARCHAR, fname VARCHAR, 
							ssdeep VARCHAR, PRIMARY KEY (filename, fname))''')
		con.commit()

		

		codecon =  sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract']))
		codecur = 	codecon.cursor()


		fnhashCount = 0
		fnSkipCount = 0

		rows = codecur.execute("SELECT filename, fname, llcode from function")
		for row in rows:
			filename = row[0]
			fname = row[1]
			llcode = row[2]
			fhash = ssdeep.hash(llcode)
			debug(f'ssdeep of {filename}:{fname} ', fhash)
			try:
				cur.execute("INSERT INTO funcll_ssdeep (filename,fname, ssdeep) values(?,?,?)",
					(
						filename, 
						fname,
						fhash
					)
				)
				con.commit()
				fnhashCount += 1
			
			except sqlite3.IntegrityError:
				fnSkipCount += 1
				pass
		elog(f"calculated {fnhashCount} hashes, skipped {fnSkipCount}")


	if "simhash" == action:
		con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
		cur = con.cursor()
		cur.execute('''
			CREATE TABLE IF NOT EXISTS funcsimhash (filename VARCHAR, fname VARCHAR, 
							simhash VARCHAR, PRIMARY KEY (filename, fname))''')
		con.commit()

		fnhashCount = 0
		fnSkipCount = 0

		tokencon =  sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract']))
		tokencur = 	tokencon.cursor()

		rows = tokencur.execute("SELECT filename, fname, tokens from token")
		for row in rows:
			filename = row[0]
			fname = row[1]
			functokens = row[2]

			# if value too large to be INTEGER, store as string
			# simh = str(Simhash(get_features(functokens)).value) 
			# test with and without get_features?
			simh = str(SimHash(functokens, 64, 16).value())

			# for t in functokens.split():
			# 	m.update(t.encode('utf8'))
			# 	# m.update(t)

		
			
			# debug('hash:', hashvals)
			try:
				cur.execute("INSERT INTO funcsimhash (filename,fname, simhash) values(?,?,?)",
					(
						filename, 
						fname, 
						simh
					)
				)
				con.commit()
				fnhashCount += 1
			
			except sqlite3.IntegrityError:
				fnSkipCount += 1
				pass
			
			# import code
			# code.interact(local=locals())
		elog(f"calculated {fnhashCount} hashes, skipped {fnSkipCount}")

	if "tlsh" == action:
		con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
		cur = con.cursor()
		cur.execute('''
			CREATE TABLE IF NOT EXISTS functlsh (filename VARCHAR, fname VARCHAR, 
							tlsh VARCHAR, PRIMARY KEY (filename, fname))''')
		con.commit()

		fnhashCount = 0
		fnSkipCount = 0

		tokencon =  sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['extract']))
		tokencur = 	tokencon.cursor()

		rows = tokencur.execute("SELECT filename, fname, tokens from token")
		for row in rows:
			filename = row[0]
			fname = row[1]
			functokens = row[2]

			
			if len(functokens) <= 50: # tlsh has to perform over data of 50 bytes
				fnSkipCount += 1
				continue
			if type(functokens) == str:
				functokens = functokens.encode()
			tlsh_hash = tlsh.hash(functokens)
		
			# debug('hash:', hashvals)
			try:
				cur.execute("INSERT INTO functlsh (filename,fname, tlsh) values(?,?,?)",
					(
						filename, 
						fname, 
						tlsh_hash
					)
				)
				con.commit()
				fnhashCount += 1
			
			except sqlite3.IntegrityError:
				fnSkipCount += 1
				pass
			
			# import code
			# code.interact(local=locals())
		elog(f"calculated {fnhashCount} hashes, skipped {fnSkipCount}")






	if "compare" in action:

		con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
		cur = con.cursor()
		
		if funcNames == None:
			print("please specify function name(s) to compare in -f ")
			exit(1)

		if ALGO == "minhash":
			# mapping < CONCAT(funcname,filename) : hashobjs>
			funcnameFilename_hashobjs = {}
			jaccard_dists = []

			# print CSV header
			print('filefunc0,filefunc1,permutations,jaccard_dist')

			for funcName in funcNames.split(','):
				rows = cur.execute("SELECT filename,fname,hashvals FROM funcminhash WHERE fname LIKE ? AND numperms=?", (funcName, MINHASH_PERMS))
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


		elif ALGO == "ssdeep":
			tablename = 'funcssdeep'
			if "ll" in action:
				tablename = 'funcll_ssdeep'

			funcnameFilename_hashobjs = {}
			scores = []

			# print CSV header
			print('filefunc0,filefunc1,score')

			for funcName in funcNames.split(','):
				rows = cur.execute("SELECT filename,fname,ssdeep FROM %s WHERE fname LIKE ?" % tablename, (funcName,))
				for r in rows:
					filename = r[0]
					fname = r[1]
					fname_filename = filename + ":" + fname
					ssdeepStr = r[2]
					# debug(f"{filename}:{fname}")
					funcnameFilename_hashobjs[fname_filename] = ssdeepStr
			# print(funcnameFilename_hashobjs)
			for p in itertools.combinations(funcnameFilename_hashobjs.keys(), 2):
				filefunc0 = p[0]
				filefunc1 = p[1]
				s0 = funcnameFilename_hashobjs[filefunc0]
				s1 = funcnameFilename_hashobjs[filefunc1]
				score = ssdeep.compare(s0, s1)
				scores.append(score)

				

				print(f"{filefunc0},{filefunc1},{score}")

			if len(scores) > 0:
				elog(f"min ssdeep score: {min(scores)}")
				elog(f"max ssdeep score: {max(scores)}")
				elog(f"median ssdeep score: {statistics.median(scores)}")
				elog(f"mean ssdeep score: {statistics.mean(scores)}")

		elif ALGO == "simhash" or ALGO == "simhash_ft":
			# if ALGO	 == "simhash":
			# 	tablename = 'funcsimhash'
			# elif ALGO == "simhash_ft":
			# 	tablename = 'funcsimhash_ft'


			funcnameFilename_hashobjs = {}
			distances = []

			# print CSV header
			print('filefunc0,filefunc1,distance_simhash')

			for funcName in funcNames.split(','):
				rows = cur.execute("SELECT filename,fname,simhash FROM %s WHERE fname LIKE ?" % tablename, (funcName,))
				for r in rows:
					filename = r[0]
					fname = r[1]
					fname_filename = filename + ":" + fname
					simhashStr = r[2]
					# debug(f"{filename}:{fname}")
					funcnameFilename_hashobjs[fname_filename] = simhashStr
			# print(funcnameFilename_hashobjs)
			for p in itertools.combinations(funcnameFilename_hashobjs.keys(), 2):
				filefunc0 = p[0]
				filefunc1 = p[1]
				s0 = funcnameFilename_hashobjs[filefunc0]
				s1 = funcnameFilename_hashobjs[filefunc1]
				# distance = Simhash(s0).distance(Simhash(s1))
				distance = SimHash(s0, 64, 16).distance(s1, 64, 16)
				distances.append(distance)

			
				print(f"{filefunc0},{filefunc1},{distance}")

			if len(distances) > 0:
				elog(f"min : {min(distances)}")
				elog(f"max simhash distance: {max(distances)}")
				elog(f"median simhash distance: {statistics.median(distances)}")
				elog(f"mean simhash distance: {statistics.mean(distances)}")

		elif ALGO == "tlsh":
			'''
			https://documents.trendmicro.com/assets/wp/wp-locality-sensitive-hash.pdf
			a distance score of 0 represents that 
			the files are identical (or nearly identical) and scores above that represent greater distance between the 
			documents. A higher score should represent that there are more differences between the documents

			The TLSH scheme has very low false positive detection capabilities at thresholds <= 30 and very high 
			detection rates for thresholds closer to 100
			'''
			tablename = 'functlsh'
			if THRESHOLD == None:
				THRESHOLD = 100 # <= 100
			funcnameFilename_hashobjs = {}
			distances = []
			skipped=0

			# print CSV header
			print('filefunc0,filefunc1,difference_tlsh')

			for funcName in funcNames.split(','):
				rows = cur.execute("SELECT filename,fname,tlsh FROM %s WHERE fname LIKE ?" % tablename, (funcName,))
				for r in rows:
					filename = r[0]
					fname = r[1]
					fname_filename = filename + ":" + fname
					tlsh_hash = r[2]
					# debug(f"{filename}:{fname}")
					funcnameFilename_hashobjs[fname_filename] = tlsh_hash
			# print(funcnameFilename_hashobjs)
			for p in itertools.combinations(funcnameFilename_hashobjs.keys(), 2):
				filefunc0 = p[0]
				filefunc1 = p[1]

				t0 = funcnameFilename_hashobjs[filefunc0]
				t1 = funcnameFilename_hashobjs[filefunc1]
				# using diffxlen instead of diff to add in containment of a repeating patterns
				if t0 != "TNULL" and t1 != "TNULL":
					distance = tlsh.diffxlen(t0,t1)
				else:
					skipped += 1
				distances.append(distance)

			
				print(f"{filefunc0},{filefunc1},{distance}")

			if len(distances) > 0:
				elog(f"min : {min(distances)}")
				elog(f"max tlsh distance: {max(distances)}")
				elog(f"median tlsh distance: {statistics.median(distances)}")
				elog(f"mean tlsh distance: {statistics.mean(distances)}")
			print('skipped because of TNULL:',skipped)

	# confusion matrix
	if "confusion" == action:
		con = sqlite3.connect(os.path.join(DATADIR,"db",OUTPUT_DBPATHS['hash']))
		cur = con.cursor()
		
		if ALGO == "minhash":

			if THRESHOLD == None:
				THRESHOLD = 0.5

			# mapping < CONCAT(funcname,filename) : hashobjs>
			funcnameFilename_hashobjs = {}
			jaccard_dists = []

			# print CSV header
			# print('filefunc0,filefunc1,permutations,jaccard_dist')

			# true pos, false negatie ..
			tpos, fneg, fpos, tneg = 0,0,0,0

			# get evyerthing
			rows = cur.execute("SELECT filename,fname,hashvals FROM funcminhash WHERE numperms=?", (MINHASH_PERMS,))
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
				# jaccard_dists.append(jaccardi)

				f0 = filefunc0.split(":")[1]
				f1 = filefunc1.split(":")[1]
				if (f0 == f1): # same func name
					if jaccardi >= THRESHOLD:
						tpos += 1
					else:
						fneg += 1
				else: # diff function name
					if jaccardi >= THRESHOLD:
						fpos += 1
					else:
						tneg += 1


			print(f"threshold:{THRESHOLD}\ntp:{tpos}\ntn:{tneg}\nfp:{fpos}\nfn:{fneg}")
			print_confusion_matrix('minhash', tpos,fpos,tneg,fneg)
# 			print('''
# |minhash data matrix|match|no match|
# |------------------------|-----|---------|
# |\tsame funcname|{:>8}|{:>9}|
# |\tdiff funcname|{:>8}|{:>9}|
# 			'''.format(tpos,fneg,fpos,tneg))

# 			print('''
# |minhash confusion matrix|match|no match|
# |------------------------|-----|---------|
# |\tsame funcname|{:>8.3f}|{:>9.3f}|
# |\tdiff funcname|{:>8.3f}|{:>9.3f}|
# 			'''.format(tpos/(tpos+fneg),fneg/(tpos+fneg),fpos/(fpos+tneg),tneg/(fpos+tneg)))
# 			# print("minhash confusion matrix")


		elif ALGO == "ssdeep":

			if THRESHOLD == None:
				THRESHOLD = 0

			tablename = 'funcssdeep'
			if "ll" in action:
				tablename = 'funcll_ssdeep'

			funcnameFilename_hashobjs = {}
			tpos, fneg, fpos, tneg = 0,0,0,0

			rows = cur.execute("SELECT filename,fname,ssdeep FROM %s" % tablename)
			for r in rows:
				filename = r[0]
				fname = r[1]
				fname_filename = filename + ":" + fname
				ssdeepStr = r[2]
				# debug(f"{filename}:{fname}")
				funcnameFilename_hashobjs[fname_filename] = ssdeepStr
			# print(funcnameFilename_hashobjs)
			for p in itertools.combinations(funcnameFilename_hashobjs.keys(), 2):
				filefunc0 = p[0]
				filefunc1 = p[1]
				s0 = funcnameFilename_hashobjs[filefunc0]
				s1 = funcnameFilename_hashobjs[filefunc1]
				score = ssdeep.compare(s0, s1)
				# scores.append(score)

				f0 = filefunc0.split(":")[1]
				f1 = filefunc1.split(":")[1]
				if (f0 == f1): # same func name
					if score > THRESHOLD:
						tpos += 1
					else:
						fneg += 1
				else: # diff function name
					if score > THRESHOLD:
						fpos += 1
					else:
						tneg += 1


			print(f"threshold:{THRESHOLD}\ntp:{tpos}\ntn:{tneg}\nfp:{fpos}\nfn:{fneg}")
			print_confusion_matrix('ssdeep', tpos, fpos, tneg, fneg)

		elif ALGO == "simhash" or ALGO == "simhash_ft":
			if ALGO	 == "simhash":
				tablename = 'funcsimhash'
			elif ALGO == "simhash_ft":
				tablename = 'funcsimhash_ft'

			if THRESHOLD == None:
				THRESHOLD = 10

			tpos, fneg, fpos, tneg = 0,0,0,0
			funcnameFilename_hashobjs = {}

			rows = cur.execute("SELECT filename,fname,simhash FROM %s" % tablename)
			for r in rows:
				filename = r[0]
				fname = r[1]
				fname_filename = filename + ":" + fname
				simhashStr = r[2]
				# debug(f"{filename}:{fname}")
				funcnameFilename_hashobjs[fname_filename] = simhashStr
			# print(funcnameFilename_hashobjs)
			for p in itertools.combinations(funcnameFilename_hashobjs.keys(), 2):
				filefunc0 = p[0]
				filefunc1 = p[1]
				s0 = funcnameFilename_hashobjs[filefunc0]
				s1 = funcnameFilename_hashobjs[filefunc1]
				distance = SimHash(s0, 64, 16).distance(SimHash(s1, 64, 16))
			
				# print(f"{filefunc0},{filefunc1},{distance}")
				f0 = filefunc0.split(":")[1]
				f1 = filefunc1.split(":")[1]
				if (f0 == f1): # same func name
					if distance <= THRESHOLD: # small distance (<= t) is a match
						tpos += 1
					else:
						fneg += 1
				else: # diff function name
					if distance <= THRESHOLD:
						fpos += 1
					else:
						tneg += 1

			print(f"threshold:{THRESHOLD}\ntp:{tpos}\ntn:{tneg}\nfp:{fpos}\nfn:{fneg}")
			print_confusion_matrix('simhash', tpos, fpos, tneg, fneg)


		if ALGO == "tlsh":

			if THRESHOLD == None:
				THRESHOLD = 100

			# mapping < CONCAT(funcname,filename) : hashobjs>
			funcnameFilename_hashobjs = {}

			skipped = 0
			# print CSV header
			# print('filefunc0,filefunc1,permutations,jaccard_dist')

			# true pos, false negatie ..
			tpos, fneg, fpos, tneg = 0,0,0,0

			# get evyerthing
			rows = cur.execute("SELECT filename,fname,tlsh FROM functlsh")
			for r in rows:
				filename = r[0]
				fname = r[1]
				fname_filename = filename + ":" + fname
				tlsh_hash = r[2]
				funcnameFilename_hashobjs[fname_filename] = tlsh_hash


			for p in itertools.combinations(funcnameFilename_hashobjs.keys(), 2):
				filefunc0 = p[0]
				filefunc1 = p[1]
				t0 = funcnameFilename_hashobjs[filefunc0]
				t1 = funcnameFilename_hashobjs[filefunc1]
				
				if t0 != "TNULL" and t1 != "TNULL":
					distance = tlsh.diffxlen(t0,t1)
				else:
					skipped += 1	
				f0 = filefunc0.split(":")[1]
				f1 = filefunc1.split(":")[1]
				if (f0 == f1): # same func name
					if distance <= THRESHOLD: # small distance (<= t) is a match
						tpos += 1
					else:
						fneg += 1
				else: # diff function name
					if distance <= THRESHOLD:
						fpos += 1
					else:
						tneg += 1

			print('skipped:',skipped)
			print(f"threshold:{THRESHOLD}\ntp:{tpos}\ntn:{tneg}\nfp:{fpos}\nfn:{fneg}")
			print_confusion_matrix('tlsh', tpos, fpos, tneg, fneg)

	print(f"done, elapsed {time.time() - start} seconds")
