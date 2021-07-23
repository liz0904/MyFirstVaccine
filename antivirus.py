#-*-coding:utf-8 -*-
import sys  
import hashlib
import os

VirusDB=[   #MD5 Hash: Name of Virus
    '68:44d88612fea8a8f36de82e1278abb02f:EICAR Test', #eicar.txt
    '62:99e22455ab3caa37e63a262eceb443dd: Dummy Test'  #dummy.txt
]

vdb=[]  #가공된 악성코드 DB 저장
vsize=[]    #악성코드의 파일 크기 저장

def MakeVirusDB():
    for pattern in VirusDB:
        t=[]
        v = pattern.split(':')   
        t.append(v[1]) #Add MD5 Hash
        t.append(v[2]) #Add Name of Virus
        vdb.append(t)   #Save to vdb
        
        size=int(v[0]) #악성코드 파일 크기
        if vsize.count(size)==0:
            vsize.append(size)
 
#악성코드 검사 함수 
def SearchVDB(fmd5):
    for t in vdb:
        if t[0]==fmd5:  #Compare MD5
            return True, t[1]   #Return Virus name
            
    return False, ''    #No Virus

if __name__=='__main__':
    MakeVirusDB()
    
    #커맨드라인 입력 방식 체크
    if len(sys.argv) !=2:
        print 'Usage: antivirus.py [file]'
        exit(0)
       
    fname = sys.argv[1] #악성코드 검사 대상 파일
    
    size=os.path.getsize(fname) #검사 대상 파일 크기 구하기
    if vsize.count(size):
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
    else :
            print '%s : ok' %(fname)

