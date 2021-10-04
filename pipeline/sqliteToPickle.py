#!/usr/bin/env python3

import sys
import sqlite3
import json
import time
import os
import pickle

if len(sys.argv) < 2:
	print("missing path to db file")
	print('usage: %s <path to sqlite3 db> [outfile]' % sys.argv[0])
	exit(0)

dbpath = sys.argv[1]
outfile = None

if len(sys.argv) >= 3:
	outfile = sys.argv[2]

MINHASH_PERMS = 64
THRESHOLD = 0.5
VERBOSE = False

start = time.time()


'''
<number:set_of_filename:funcname>

'''
minhashdb = {}

# connect to db
# dbpath = os.path.join(DATADIR,"db", )

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
			minhashdb[i] = []

		minhashdb[i].append(fname_filename)


	# print(f"{filename}:{fname}")

	
print(f"finished loading minhashdb, elapsed {time.time() - start}")
print(f"{len(allfilefuncs)} filename:funcname total")

if outfile == None:
	outfile = os.path.basename(dbpath)+".pkl"
with open(outfile, "wb") as f:
	f.write(pickle.dumps(minhashdb))

print(f"stored json file at {outfile}, elapsed {time.time() - start}")