#-*- coding:utf-8 -*-
import sys
import zlib
import hashlib
import os

#파일 암호화
def main():
    if len(sys.argv) != 2:
        print 'Usage: kmake.py [file]'
        return

    fname=sys.argv[1] #암호화 대상 파일
    tname=fname

    fp=open(tname, 'rb')
    buf=fp.read()
    fp.close()

    buf2=zlib.compress(buf) #대상 파일 내용 압축

    buf3=''
    for c in buf2:  #0xFF로 압축된 내용 XOR 연산
        buf3+=chr(ord(c) ^0xFF)

    buf4='KAVM' + buf3 #헤더 생성

    f=buf4
    for i in range(3):
        md5=hashlib.md5()
        md5.update(f)
        f=md5.hexdigest()

    buf4+=f #암호화된 내용 뒤에 MD5 추가

    kmd_name=fname.split('.')[0]+'.kmd'
    fp=open(kmd_name, 'wb')  #kmd 확장자로 암호파일 만들기
    fp.write(buf4)
    fp.close()

    print '%s -> %s' % (fname, kmd_name)    #결과 출력


if __name__=='__main__':
    main()
