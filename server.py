#!/usr/bin/env python3
from flask import Flask, render_template, request,jsonify
from werkzeug.utils import secure_filename
import pickle
import time
import os
from bcd import lift, extract_functions_retdecLL,tokenize,lookupPath,indexPath

# this is really bad for production use - you will most likely find the app really slow during a threaded function..
import _thread

app = Flask(__name__,
            static_url_path='',
            static_folder='templates',
            template_folder='templates')
UPLOADPATH = 'uploads'

MINHASH_PERMS = 64
THRESHOLD = 0.5
VERBOSE = False

PICKLEFILE = 'db_dict.pkl'
# OUTPUT_DBPATHS = {'extract':'ll_extract.db', 'tokenize':'tokens.db', 'hash':'hashes.db'}
MINHASH_PERMS = 64
MINHASHDB = {}

@app.route('/')
def index():
   return render_template('index.html', hashcount=len(MINHASHDB))
    
@app.route('/upload', methods = ['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        import pprint
        pprint.pprint(request.files)

        # files = request.files
        # import code
        # code.interact(local=locals())

        for f in request.files.getlist('files[]'):
            if f.filename != "":
                print('secure filename: ', secure_filename(f.filename))
                safepath = os.path.join(UPLOADPATH, secure_filename(f.filename))
                f.save(safepath)
                # threadname = 'lookup-'+safepath 
                _thread.start_new_thread(lookupPath, (safepath,))

    
        return jsonify({'message':'upload complete, processing file(s)...', 'success':1})
        
start = time.time()

if __name__ == '__main__':
	# load pickle db
	# this file has to exist - if not, create it
	try:
		f = open(PICKLEFILE,'rb')
		MINHASHDB = pickle.load(f)
	except FileNotFoundError:
		print('db pickle file not found - create it or modify the PICKLEFILE variable in the code')
	
	print(f"finished loading db dictionary, elapsed {time.time() - start}")
	print(f"hashes in db: {len(MINHASHDB)}")
	if len(MINHASHDB) == 0:
		print("warning: no data in db")

	app.run(debug = True)