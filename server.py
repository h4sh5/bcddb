#!/usr/bin/env python3
from flask import Flask, render_template, request,jsonify
from werkzeug.utils import secure_filename
import pickle
import time
import os
from bcd import lift, extract_functions_retdecLL,tokenize,lookupPath,indexPath

import hashlib

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

CURRENTRESULTS = {}
CURRENTDONE = False
ANALYSIS_TIME = 0

@app.route('/')
def index():
   return render_template('index.html', hashcount=len(MINHASHDB))
    
def lookupPathAndSave(filepath):
    '''
    start new thread, save result in CURRENTRESULTS
    '''
    global CURRENTDONE, CURRENTRESULTS, ANALYSIS_TIME

    analysisStart = time.time()
    CURRENTRESULTS = lookupPath(filepath, db=MINHASHDB)
    ANALYSIS_TIME = time.time() - analysisStart 
    CURRENTDONE = True



@app.route('/upload', methods = ['GET', 'POST'])
def upload_file():
    global CURRENTDONE
    
    if request.method == 'POST':
        import pprint
        pprint.pprint(request.files)

        results = {}

        # files = request.files
        # import code
        # code.interact(local=locals())

        for f in request.files.getlist('files[]'):
            if f.filename != "":
                print('secure filename: ', secure_filename(f.filename))
                safepath = os.path.join(UPLOADPATH, secure_filename(f.filename))
                f.save(safepath)
                # threadname = 'lookup-'+safepath 
                # need to return this somehow - maybe just let it load synchronously (want to avoid global vars?)
                # and just have a progress wheel in the front end
                # matches = lookupPath(safepath)
                # results[f.filename] = matches
                CURRENTDONE = False
                _thread.start_new_thread(lookupPathAndSave, (safepath,))


        return jsonify({'message':'upload complete, processing file(s)...', 'success':1})

@app.route("/isdone")
def isDone():
    '''
    use action to check if processing is done
    '''
    if CURRENTDONE == True:
        return 'true'
    return 'false'
        
@app.route('/report')
def report():
    '''
    results page
    '''

    return render_template('report.html', analysis_time=ANALYSIS_TIME, results=CURRENTRESULTS)


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