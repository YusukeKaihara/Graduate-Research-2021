import json
import glob
import os
import pickle
import random
import collections

api_list=[]
api_count={}
paths = glob.glob("C:/Users/Kaihara/python/familygroup/Backdoor.Win32.Androm\\*")
path = random.sample(paths,k=10)
print(path)
for i in range(10):
    data = path[i]
    with open(data) as f:
         j = json.load(f)
         apis = [item['api'] for item in j['behavior']['processes'][1]['calls']]
         
api_count = collections.Counter(apis)
print(api_count)

with open('api_count.pickle', mode='wb') as fo:
    pickle.dump(api_count,fo)
    
with open('file.pickle', mode='wb') as fi:
    pickle.dump(path,fi)

                 


