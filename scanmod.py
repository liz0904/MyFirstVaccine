#-*-coding:utf-8 -*-
import hashlib
import os

#악성코드 검사 함수
def SearchVDB(vdb, fmd5):
    for t in vdb:
        if t[0]==fmd5:  #MD5 해시가 같은지 비교
            return True, t[1]   #Return Virus name

    return False, ''    #No Virus


#MD5를 이용해 악성코드 검사
def ScanMD5(vdb, vsize, fname):
    ret=False   #악성코드 발견 유무
    vname =''    #발견된 악성코드명

    size=os.path.getsize(fname) #검사 대상 파일 크기 구하기
    if vsize.count(size):
        fp=open(fname, 'rb')  #read as binary
        buf=fp.read()
        fp.close()

        m=hashlib.md5()
        m.update(buf)  # get MD5 hash of buf
        fmd5=m.hexdigest()

        ret, vname =SearchVDB(vdb, fmd5)  # 악성코드 검사

    return ret, vname

#특정 위치 검색법을 이용해 악성코드 검사
def ScanStr(fp, offset, mal_str):
    size=len(mal_str)   #악성코드 진단 문자열의 길이

    #특정 위치에 악성코드 진단 문자열이 존재하는지 체크
    fp.seek(offset) #악성코드 문자열이 있을 것 같은 위치(예상)으로 이동
    buf=fp.read(size)

    if buf==mal_str:    #악성코드 O
        return True
    else:               #악성코드 X
        return Ralse