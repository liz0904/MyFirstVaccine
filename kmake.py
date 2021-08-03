'''
<virus.db 파일은 누구나 편집이 가능하기 때문에 해커가 마음대로 조작하지 못하게 암호화해주는 과정>
1. 암호 대상 파일을 인자값으로 입력받은 뒤, 만약 인자값이 없다면 오류메세지 출력
2. 정상적으로 입력되었다면, 파일 전체 내용을 읽은 다음 zlib으로 압축
3. 압축된 내용을 1 byte 단위로 0xFF로 XOR 연산을 수행한 뒤 암호화
4. 암호화까지 완료되면 KAVM 문자열을 추가하고, 이 전체 내용의 MD5를 구한 다음, 암호화된 내용 뒤에 MD5를 추가
5. 생성된 암호화 내용을 기존 확장자에서 kmd 확장자로 변경한 뒤 파일 생성
'''

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
    fp=pen(kmd_name, 'wb')  #kmd 확장자로 암호파일 만들기
    fp.write(buf4)
    fp.close()

    print '%s -> %s' % (fname, kmd_name)    #결과 출력


if __name__=='__main__':
    main()
