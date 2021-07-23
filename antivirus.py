<<<<<<< HEAD
import hashlib
import os

fp=open('eicar.txt', 'rb')  #read as binary
fbuf=fp.read()
fp.close()

m=hashlib.md5() 
m.update(fbuf)  # get MD5 hash of fbuf
fmd5=m.hexdigest()

if fmd5 == '44d88612fea8a8f36de82e1278abb02f':  #Compare with MD5 of eicar.txt
    print 'Virus'
    os.remove('eicar.txt')  #remove antiVirus File
else :
    print 'No Virus'
=======
#-*-coding:utf-8 -*-
import sys  
import hashlib
import os

VirusDB=[   #MD5 Hash: Name of Virus
    '44d88612fea8a8f36de82e1278abb02f:EICAR Test', #eicar.txt
    '99e22455ab3caa37e63a262eceb443dd: Dummy Test'  #dummy.txt
]

vdb=[]

def MakeVirusDB():
    for pattern in VirusDB:
        t=[]
        v = pattern.split(':')   
        t.append(v[0]) #Add MD5 Hash
        t.append(v[1]) #Add Name of Virus
        vdb.append(t)   #Save to vdb
       
def SearchVDB(fmd5):
    for t in vdb:
        if t[0]==fmd5:  #Compare MD5
            return True, t[1]   #Return Virus name
            
    return False, ''    #No Virus
    
if __name__=='__main__':
    MakeVirusDB()
    
    if len(sys.argv) !=2:
        print 'Usage: antivirus.py [file]'
        exit(0)
       
    fname = sys.argv[1]
    fp=open(fname, 'rb')  #read as binary
    buf=fp.read()
    fp.close()

    m=hashlib.md5() 
    m.update(buf)  # get MD5 hash of buf
    fmd5=m.hexdigest()

    ret, vname=SearchVDB(fmd5)  # find Virus
    if ret == True:  #Compare with MD5
        print '%s: %s' % (fname, vname)
        os.remove(fname)  #remove antiVirus File
    else :
        print '%s : ok' %(fname)
>>>>>>> 4b2f061 (악성코드 DB 리스트 추가)
