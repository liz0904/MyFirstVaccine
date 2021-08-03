#-*-coding:utf-8 -*-
import sys
import hashlib
import os
import zlib
import StringIO

print (os.path.getsize('eicar.txt'))
print (os.path.getsize('dummy.txt'))


VirusDB=[ ] #악성코드 패턴 저장
vdb=[]  #가공된 악성코드 DB 저장
vsize=[]    #악성코드의 파일 크기 저장

#KMD 파일 복호화
def DecodeKMD(fname):
    try:
        fp=open(fname, 'rb')
        buf=fp.read()
        fp.close()

        buf2=buf[:-32]  #암호화 된 내용 분리
        fmd5=buf[-32:] #MD5 분리

        f=buf2
        for i in range(3):  #암호화 내용의 MD5 구하기
            md5=hashlib.md5()
            md5.update(f)
            f=md5.hexdigest()

        if f!=fmd5: #위 결과 파일에서 분리된 MD5가 같은가?
            raise SystemError

        buf3=''
        for c in buf2[4:]:  #0xFF로 XOR 한다
            buf3+=chr(ord(c) ^0xFF)

        buf4=zlib.decompress(buf3)
        return buf4 #성공 했다면 복호화된 내용을 리턴

    except:
        pass

    return None #오류가 있다면 None 리턴

#virus.kmd 파일에서 악성코드 패턴 로딩
def LoadVirusDB():
    buf=DecodeKMD('virus.kmd')  #악성코드 패턴을 복호화
    fp=StringIO.StringIO(buf)

    while True:
        line=fp.readline()  #악성코드 패턴 한줄읽기
        if not line : break

        line=line.strip()   #엔터 제거
        VirusDB.append(line)
    fp.close()

#VirusDB 가공 후 vdb에 저장
def MakeVirusDB():
    for pattern in VirusDB:
        t=[]
        v = pattern.split(':')
        t.append(v[1]) #Add MD5 Hash
        print v[1]
        t.append(v[2]) #Add Name of Virus
        vdb.append(t)   #Save to vdb

        size=int(v[0]) #악성코드 파일 크기
        if vsize.count(size)==0:
            vsize.append(size)

#악성코드 검사 함수
def SearchVDB(fmd5):
    for t in vdb:
        if t[0]==fmd5:  #MD5 해시가 같은지 비교
            return True, t[1]   #Return Virus name

    return False, ''    #No Virus

if __name__=='__main__':
    LoadVirusDB()   #악성코드 패턴 읽어오기
    MakeVirusDB()   #악성코드 DB 가공

    #커맨드라인 입력 방식 체크
    if len(sys.argv) !=2:
        print ('Usage: antivirus.py [file]')
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
            print ('%s: %s' % (fname, vname))
            os.remove(fname)  #remove antiVirus File
        else :
            print ('%s : ok' %(fname))
    else :
            print ('%s : ok' %(fname))

