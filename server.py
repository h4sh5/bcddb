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

# sorry for all the global variables and screaming

UPLOADPATH = 'uploads'

MINHASH_PERMS = 64
THRESHOLD = 0.5
VERBOSE = False

PICKLEFILE = 'db_dict.pkl'
# OUTPUT_DBPATHS = {'extract':'ll_extract.db', 'tokenize':'tokens.db', 'hash':'hashes.db'}
MINHASH_PERMS = 64
MINHASHDB = {}

CURRENTFILEINFO = {}
CURRENTRESULTS = {}
CURRENTDONE = False
ANALYSIS_TIME = 0

@app.route('/')
def index():
   return render_template('index.html.j2', hashcount=len(MINHASHDB))
    
def lookupPathAndSave(filepath):
    '''
    start new thread, save result in CURRENTRESULTS
    '''
    global CURRENTDONE, CURRENTRESULTS, ANALYSIS_TIME,CURRENTFILEINFO

    analysisStart = time.time()
    CURRENTRESULTS = lookupPath(filepath, db=MINHASHDB)
    ANALYSIS_TIME = time.time() - analysisStart 
    CURRENTFILEINFO['filename'] = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        CURRENTFILEINFO['md5'] = hashlib.md5(f.read()).hexdigest()
    CURRENTDONE = True
    os.remove(filepath)


def indexPathAndSave(filepath):
    global MINHASHDB, CURRENTDONE
    indexPath(filepath, db=MINHASHDB)
    with open(PICKLEFILE, 'wb') as f:
        pickle.dump(MINHASHDB, f)
    print(f'db updated in {PICKLEFILE}')
    CURRENTDONE = True
    os.remove(filepath)

@app.route('/upload/<action>', methods = ['GET', 'POST'])
def upload_file(action):
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
                CURRENTDONE = False
                if action == 'search':
                    print('searching...')
                    _thread.start_new_thread(lookupPathAndSave, (safepath,))
                elif action == 'index':
                    print('indexing...')
                    _thread.start_new_thread(indexPathAndSave, (safepath,))



        return jsonify({'message':'upload complete, processing file(s)...', 'success':1})

@app.route("/isdone")
def isDone():
    '''
    use action to check if processing is done
    '''
    if CURRENTDONE == True:
        return 'true'
    return 'false'


def averageScore(resultTuples):
    '''
    utility function to pass to flask;
    calculate the average score in a list of result tuples 
    e.g.
    [ ('filename:funcname': 0.5), ('filename:funcname1': 0.8), ..]
    '''
    total = 0
    counter = 0
    for name,score in resultTuples:
        total += score
        counter += 1

    return float(total / counter)


def maxScore(resultTuples):
    '''
    same as averageScore, but max
    '''
    max_score = 0
    for name,score in resultTuples:
        if max_score < score:
            max_score = score

    return max_score


@app.route('/report')
def report():
    '''
    results page
    '''
    # if CURRENTRESULTS
    results = CURRENTRESULTS
    
    return render_template('report.html.j2', analysis_time=ANALYSIS_TIME, results=CURRENTRESULTS, fileinfo=CURRENTFILEINFO, 
        averageScore=averageScore, maxScore=maxScore) # also utility functions


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