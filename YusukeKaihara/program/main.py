from db import getDatabase, closeDatabase
from sklearn import svm
import argparse
import glob
import sys
import json
import pprint
import pickle
import random
import collections
import numpy as np
import pandas as pd
import csv
from sklearn.svm import SVC
from sklearn.metrics import make_scorer
from sklearn.metrics import accuracy_score, recall_score, precision_score
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import GridSearchCV
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from imblearn.under_sampling import ClusterCentroids, RandomUnderSampler, NearMiss
from imblearn.pipeline import make_pipeline
from sklearn.pipeline import Pipeline
from gensim.models.doc2vec import Doc2Vec, TaggedDocument

parser = argparse.ArgumentParser(description='main function')

parser.add_argument(
    'process', 
    help='')

parser.add_argument(
    '-m', '--method', 
    help='')

parser.add_argument(
    '--dm', type=int, default=1, 
    help='')

parser.add_argument(
    '--size', type=int, 
    help='')

parser.add_argument(
    '--window', type=int,
    help='')

parser.add_argument(
    '--mincount', type=int,
    help='')

parser.add_argument(
    '--ml',
    help='')

parser.add_argument(
    '-v', '--vector',
    help='')

args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
# process0
if args.process == '0':
    
    db = getDatabase()
    
    paths = glob.glob("C:/Users/Kaihara/python/familygroup/Backdoor.Win32.Androm\\*")

    dic = {}
    with open('file.pickle', mode='rb') as fi:
        file_list =  pickle.load(fi)
    for path in paths:
        if path in file_list:
            continue
        try:
        
            with open(path, 'r') as f,open('api_count.pickle', mode='rb') as fi:
                file_json = json.load(f)
                api_list = pickle.load(fi)
                
            sha1 = file_json['virustotal']['sha1']
            apis = [item['api'] for item in file_json['behavior']['processes'][1]['calls']]
            functions = [function for function in file_json['behavior']['summary'].keys()]

        except:

            
            continue
        
        if apis != [] and functions != []:
            
            dic[sha1] = {'api':apis, 'function':functions}

    db['sample'] = dic
    db.sync()

    closeDatabase(db)


    # process1.1　
if args.process == '1.1':
    
    
    db = getDatabase()
    
    paths = glob.glob("C:/Users/Kaihara/python/familygroup/Backdoor.Win32.Androm\\*")

    dic = {}
    with open('file.pickle', mode='rb') as fi:
        file_list =  pickle.load(fi)
    for path in paths:
        if path in file_list:
            continue
        try:
            with open(path, 'r') as f,open('api_count.pickle', mode='rb') as fi:
                file_json = json.load(f)
                api_count = pickle.load(fi)
            sha1 = file_json['virustotal']['sha1']
            apis = [item['api'] for item in file_json['behavior']['processes'][1]['calls']]
            functions = [function for function in file_json['behavior']['summary'].keys()]
            api_list = list(api_count.keys())
            api_diff = set(api_list) - set(apis)
            api_difflist = list(api_diff)
     
   
        
    
            api_append = random.sample(api_difflist,k=3) #付加するapiリスト

            sha1_new = sha1 + '_1'
            api_new= apis + api_append
        except:
            continue
        
        if apis != [] and functions != []:
            
            dic[sha1_new] = {'api':api_new, 'function':functions}

    db['sample'] = dic
    db.sync()

    closeDatabase(db)
    
     
        # process1.2 重み付き
if args.process == '1.2':
    w = []
    db = getDatabase()
    
    paths = glob.glob("C:/Users/Kaihara/python/familygroup/Backdoor.Win32.Androm\\*")

    dic = {}
    with open('file.pickle', mode='rb') as fi:
        file_list =  pickle.load(fi)
    for path in paths:
        if path in file_list:
            continue
        try:
        
            with open(path, 'r') as f,open('api_count.pickle', mode='rb') as fi:
                file_json = json.load(f)
                api_count = pickle.load(fi)
                
            sha1 = file_json['virustotal']['sha1']
            apis = [item['api'] for item in file_json['behavior']['processes'][1]['calls']]
            functions = [function for function in file_json['behavior']['summary'].keys()]
            api_list = list(api_count.keys())
            api_diff = set(api_list) - set(apis)
            api_difflist = list(api_diff)
            for i in range(len(api_difflist)):                  
                w.append(api_count[api_difflist[i]])
         

            api_append = random.choices(api_difflist,k=3,weights=w) #付加するapiリスト
            sha1_new = sha1 + '_1'
            api_new= apis + api_append
            w.clear()
        except:
            continue
        
        if apis != [] and functions != []:
            
            dic[sha1_new] = {'api':api_new, 'function':functions}

    db['sample'] = dic
    db.sync()

    closeDatabase(db)
    # process1.2 重み付き 反転
if args.process == '1.3':
    w = []
    db = getDatabase()
    
    paths = glob.glob("C:/Users/Kaihara/python/familygroup/Backdoor.Win32.Androm\\*")

    dic = {}
    with open('file.pickle', mode='rb') as fi:
        file_list =  pickle.load(fi)
    for path in paths:
        if path in file_list:
            continue
        try:
        
            with open(path, 'r') as f,open('api_count.pickle', mode='rb') as fi:
                file_json = json.load(f)
                api_count = pickle.load(fi)
                
            sha1 = file_json['virustotal']['sha1']
            apis = [item['api'] for item in file_json['behavior']['processes'][1]['calls']]
            functions = [function for function in file_json['behavior']['summary'].keys()]
            api_list = list(api_count.keys())
            api_diff = set(api_list) - set(apis)
            api_difflist = list(api_diff)
            for i in range(len(api_difflist)):                  
                w.append(api_count[api_difflist[i]])          
                
            w_rev = list(map(lambda y: max(w)-y+1 ,w))

            api_append = random.choices(api_difflist,k=3,weights=w_rev) #付加するapiリスト
            sha1_new = sha1 + '_1'
            api_new= apis + api_append
            w.clear()
        except:
            continue
        
        if apis != [] and functions != []:
            
            dic[sha1_new] = {'api':api_new, 'function':functions}

    db['sample'] = dic
    db.sync()

    closeDatabase(db)
    

# process2
if args.process == '2':

    db = getDatabase()

    apis = []
    for value in db['sample'].values():
        
        for api in value['api']:
            
            if api not in apis:
                apis.append(api)
        
    apis.sort()
    print(len(apis))
    db['api'] = apis
    db.sync()

    closeDatabase(db)

# process3
if args.process == '3':

    db = getDatabase()

    funcs = []

    for k, v in db['sample'].items():

        for func in v['function']:

            if func not in funcs:
                funcs.append(func)

    funcs.sort()
    print(len(funcs))
    db['func'] = funcs
    db.sync()

    closeDatabase(db)

# process4
if args.process == '4':

    if args.method == 'freq':
        
        method = args.method
        
        db = getDatabase()
    
        apis = db['api']
    
        dic = {}
        for key, value in db['sample'].items():
            
            vector = np.zeros(len(apis), dtype=float)
            
            for api in value['api']:
                
                vector[apis.index(api)] += 1
                
            dic[key] = vector

        path = method
        print(path)
        db[path] = dic
        db.sync()
        
        closeDatabase(db)

    if args.method == 'exist':

        method = args.method

        db = getDatabase()
        
        apis = db['api']
    
        dic = {}
        for key, value in db['sample'].items():
            
            vector = np.zeros(len(apis), dtype=float)
            
            for api in value['api']:
                
                vector[apis.index(api)] = 1
                
            dic[key] = vector

        path = method
        db[path] = dic
        db.sync()
        
        closeDatabase(db)

    if args.method == 'doc2vec':

        method = args.method

        dm = args.dm
        size = args.size
        # window = args.window
        # mincount = args.mincount

        db = getDatabase()
        
        keys = []
        documents = []
        for key, value in db['sample'].items():
            
            keys.append(key)
            documents.append(TaggedDocument(value['api'], [key]))
            
        model = Doc2Vec(documents, dm=dm, vector_size=size, workers=6)
        
        dic = {}
        for key in keys:
            
            dic[key] = model.docvecs[key]
            
        model.delete_temporary_training_data(keep_doctags_vectors=True, keep_inference=True)
        
        # path = method + '_' + str(dm) + '_' + str(size) + '_' + str(window) + '_' + str(mincount)
        path = method + '_' + str(dm) + '_' + str(size)
        print(path)
        db[path] = dic
        db.sync()

        closeDatabase(db)

    if args.method == 'sentenceBERT':
        
        method = args.method

        db = getDatabase()

        
        closeDatabase(db)
        
                
        
# process5		
if args.process == '5':

	vector_key = args.vector
	ml = args.ml

	db = getDatabase()
	
	funcs = db['func']

	closeDatabase(db)

	results = {}

	if ml == 'svm':	

		for func in funcs:
		
			db = getDatabase()
		
			X = []
			y = []
		
			for key, value in db['sample'].items():
		
				X.append(db[vector_key][key])
		
				if func in value['function']:
					y.append(1)
				else:
					y.append(0)
		
			closeDatabase(db)
		
			y_1_num = y.count(1)
			y_0_num = y.count(0)
		
			if y_1_num >= y_0_num:
				num = y_0_num
			else:
				num = y_1_num
		
			print("sample num = {}".format(num))
		
			X = np.array(X, dtype=float)
			y = np.array(y, dtype=int)
		
			# ESTIMATOR = make_pipeline(StandardScaler(), SVC())
		
			ESTIMATOR = make_pipeline(StandardScaler(), RandomUnderSampler(random_state=0), SVC())
			
			# ESTIMATOR = make_pipeline(StandardScaler(), ClusterCentroids(random_state=0), SVC())

			# ESTIMATOR = make_pipeline(StandardScaler(), NearMiss(version=1), SVC())
		
			PARAM_GRID = [{'svc__C': [1], 'svc__kernel': ['rbf'], 'svc__gamma':['scale']}]
		
			CV = StratifiedKFold(n_splits=10)
		
			SCORING = {'acc_score':make_scorer(accuracy_score), 'recall_score':make_scorer(recall_score), 'precision_score':make_scorer(precision_score)}
		
			clf = GridSearchCV(
				estimator=ESTIMATOR,
				param_grid=PARAM_GRID,
				scoring=SCORING,
				n_jobs=-1,
				refit=False,
				cv=CV
				)
		
			clf.fit(X, y)
		
			d = clf.cv_results_
		
			results[func] = {\
				'num':num, \
				'mean_fit_time':d['mean_fit_time'][0], \
				'std_fit_time':d['std_fit_time'][0], \
				'mean_score_time':d['mean_score_time'][0], \
				'std_score_time':d['std_score_time'][0], \
				'params':d['params'][0], \
				'mean_test_acc_score':d['mean_test_acc_score'][0], \
				'std_test_acc_score':d['std_test_acc_score'][0], \
				'mean_test_recall_score':d['mean_test_recall_score'][0], \
				'std_test_recall_score':d['std_test_recall_score'][0], \
				'mean_test_precision_score':d['mean_test_precision_score'][0], \
				'std_test_precision_score':d['std_test_precision_score'][0]\
				}
		
			pprint.pprint(results[func], width=1)
	
		l = []

		for key, value in results.items():
		
			l.append([\
				key, \
				value['num'], \
				value['mean_fit_time'], \
				value['std_fit_time'], \
				value['mean_score_time'], \
				value['std_score_time'], \
				value['params'], \
				value['mean_test_acc_score'], \
				value['std_test_acc_score'], \
				value['mean_test_recall_score'], \
				value['std_test_recall_score'],	\
				value['mean_test_precision_score'], \
				value['std_test_precision_score']\
				])

		df = pd.DataFrame(l)
		df.columns = [\
			'func', \
			'num', \
			'mean_fit_time', \
			'std_fit_time', \
			'mean_score_time', \
			'std_score_time', \
			'params', \
			'mean_test_acc_score', \
			'std_test_acc_score', \
			'mean_test_recall_score', \
			'std_test_recall_score', \
			'mean_test_precision_score', \
			'std_test_precision_score'\
			]
		df.to_csv('../result2/' + ml + '_' + vector_key + 'svm_existBackdoor.Win32.Androm3.csv')