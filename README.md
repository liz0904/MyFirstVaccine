# MyFirstVaccine
파이썬 2.7버전을 사용한 내 첫번째 백신

Virus DB 리스트에 악성파일들의 MD5 해시값과 파일명을 저장하고, 이를 악성코드 MD5 해시값과 비교해, 같으면 os 모듈의 remove 함수를 이용해 삭제해준다.

kmake.py
:virus.db 파일은 누구나 편집이 가능하기 때문에 해커가 마음대로 조작하지 못하게 암호화해주는 과정
1. 암호 대상 파일을 인자값으로 입력받은 뒤, 만약 인자값이 없다면 오류메세지 출력
2. 정상적으로 입력되었다면, 파일 전체 내용을 읽은 다음 zlib으로 압축
3. 압축된 내용을 1 byte 단위로 0xFF로 XOR 연산을 수행한 뒤 암호화
4. 암호화까지 완료되면 KAVM 문자열을 추가하고, 이 전체 내용의 MD5를 구한 다음, 암호화된 내용 뒤에 MD5를 추가
5. 생성된 암호화 내용을 기존 확장자에서 kmd 확장자로 변경한 뒤 파일 생성
![image](https://user-images.githubusercontent.com/60651715/128031602-eb16d22a-a276-4264-b432-cd9abc2bfc12.png)
