import json
import glob
import os
import re
import shutil
api_list=[]
family_list=[]
paths = glob.glob("C:/Users/Kaihara/python/dataset/ffri/2016/10/*.json") + glob.glob("C:/Users/Kaihara/Documents/FFRI_Dataset_2017/FFRI Dataset 2017/*.json")
for path in paths:
    with open(path) as f:
        j = json.load(f)
        try:
            family = j["virustotal"]["scans"]["Kaspersky"]["result"]

       
            family = family.replace(":",'.')
            family_cut =  re.findall('[\w]+.',family)
            familyname = family_cut[0]+family_cut[1]+family_cut[2]
            print(familyname)  
             
            os.makedirs(familyname,exist_ok=True)
            new_path = shutil.move(path, familyname)
        except:
            pass