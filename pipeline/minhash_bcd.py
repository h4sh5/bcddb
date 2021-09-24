#!/usr/bin/env python3

import sys,re
import getopt
from glob import glob
import sqlite3
import os
import time


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
	print("usage:\n%s"%sys.argv[0] )
	# print("action can include extract, tokenize, minhash, ssdeep, ssdeep_ll, simhash, simhash_ft compare, compare_ll, confusion_matrix")
	print('''
		arguments:
		-f funcion_name		: function name(s) to evaluate during compare (comma separated)
		-p permutations		: number of permutations for minhash, or tolerance k for simhash
		-d path/to/data		: path to data directory)
		-t threshold		: threshold for matching in minhash and simhash (e.g 0.5 for minhash, 10 for simhash)
		-v		: verbose debugging messages

		''')



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
	
elog(f"finished storing minhashdb, elapsed {time.time() - start}")
elog(f"{len(allfilefuncs)} filename:funcname total")
import code
code.interact(local=locals())

