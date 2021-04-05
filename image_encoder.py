from PIL import Image
from time import sleep
import numpy as np
import os, hashlib, random
import string

BITS=8 #length of each symbol in bits
TIME_SYM=('0','1','2','3','4','5','6','7','8','9',' ','-',':','.')
MARK_LEN=len(TIME_SYM)
HASH=''
KEY_LEN=len(hashlib.sha512(b'Hello World').hexdigest())
HASH_FUNC='SHA512'
HASH_FUNCTIONS=('SHA1',
				'SHA3_224',
				'SHA3_256',
				'SHA3_384',
				'SHA3_512',
				'SHA224',
				'SHA256',
				'SHA384',
				'SHA512',
				'MD5',
				'BLAKE2b',
				'BLAKE2s',)

def clear():
	#clear
	os.system('cls' if os.name == 'nt' else 'clear')


def to_bin(sym):
	res=''
	while sym>0:
		res=str(sym%2)+res
		sym//=2

	while len(res)<BITS:
		res='0'+res

	return res


def to_dec(sym):
	res=0
	i=0
	while len(sym)>0:
		res+=int(sym[len(sym)-1:])*(2**int(i))
		i+=1
		sym=sym[:-1]
	return res


def make_dic(mes):
	global HASH
	j=0
	dic={}
	for i in range(len(mes)):
		if mes[i] not in dic.keys():
			while True:
				if j == len(HASH):
					HASH+=random.choice('abcdefghijklmnopqrstuvwxyz0123456789')
				temp=ord(mes[i])
				temp+=ord(HASH[j])
				if temp>2**BITS:
					power=0
					t=temp
					while t>2:
						power+=1
						t/=2
					print('Symbol:',mes[i],'has too big code! Change encoding depth to '+str(int(power)+1)+' or more!')
					return -1
				t=to_bin(temp)
				if t not in dic.values():
					dic[mes[i]]=t
					j+=1
					break
				else:
					temp=ord(HASH[j])+1
					temp=chr(temp)
					st=HASH[:j]
					fn=HASH[j+1:]
					HASH=st+temp+fn
	return dic


def get_dic(mes):
	try:
		dic={}
		j=0
		for i in range(len(mes)//BITS):
			byte=mes[:BITS]
			mes=mes[BITS:]
			if byte not in dic.keys():
				value=to_dec(byte)-ord(HASH[j])
				j+=1
				sym=chr(value)
				dic[byte]=sym
		return dic
	except:
		return -1


def hashing(name,string):
	if name=='SHA1':
		return hashlib.sha1(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_224':
		return hashlib.sha3_224(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_256':
		return hashlib.sha3_256(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_384':
		return hashlib.sha3_384(string.encode('utf-8')).hexdigest()
	elif name=='SHA3_512':
		return hashlib.sha3_512(string.encode('utf-8')).hexdigest()
	elif name=='SHA224':
		return hashlib.sha224(string.encode('utf-8')).hexdigest()
	elif name=='SHA256':
		return hashlib.sha256(string.encode('utf-8')).hexdigest()
	elif name=='SHA384':
		return hashlib.sha384(string.encode('utf-8')).hexdigest()
	elif name=='SHA512':
		return hashlib.sha512(string.encode('utf-8')).hexdigest()
	elif name=='MD5':
		return hashlib.md5(string.encode('utf-8')).hexdigest()
	elif name=='BLAKE2b':
		return hashlib.blake2b(string.encode('utf-8')).hexdigest()
	elif name=='BLAKE2s':
		return hashlib.blake2s(string.encode('utf-8')).hexdigest()


def encode(source, result, mes):
	global HASH, TIME_SYM
	while True:
		key=''
		r_len=random.randint(1,50)
		for _ in range(r_len):
			key+=random.choice(string.ascii_letters+string.ascii_letters)
		break
	HASH=hashing(HASH_FUNC,key)

	im=Image.open(source)
	arr = np.array(im)
	
	temp=''
	for i in TIME_SYM:
		temp+=i
	dic=make_dic(temp+mes)
	if dic==-1:
		return -1

	mes=temp+mes+temp

	new=''
	for item in mes:
		new+=dic[item]
	mes=new

	if len(arr*3)<len(mes):
		print('Message is too long!')
		return -1

	for i in range(len(arr)):
		for j in range(len(arr[i])):
			px=arr[i][j]
			r,g,b=px[0],px[1],px[2]
			r=to_bin(r)
			g=to_bin(g)
			b=to_bin(b)
			if len(mes)>0:
				lr=mes[0]
				mes=mes[1:]
				r=r[:-1]+lr
				r=to_dec(r)
				g=to_dec(g)
				b=to_dec(b)
				arr[i][j][0]=int(r)
				arr[i][j][1]=int(g)
				arr[i][j][2]=int(b)
			else:
				break
			if len(mes)>0:
				g=to_bin(g)
				b=to_bin(b)
				lg=mes[0]
				mes=mes[1:]
				g=g[:-1]+lg
				g=to_dec(g)
				b=to_dec(b)
				arr[i][j][0]=int(r)
				arr[i][j][1]=int(g)
				arr[i][j][2]=int(b)
			else:
				break
			if len(mes)>0:
				b=to_bin(b)
				lb=mes[0]
				mes=mes[1:]
				b=b[:-1]+lb
				b=to_dec(b)
				arr[i][j][0]=int(r)
				arr[i][j][1]=int(g)
				arr[i][j][2]=int(b)
			else:
				break
		if len(mes)==0:
			break

	image=Image.fromarray(arr)
	image.save(result)
	print('Done!')
	print('Secret key:',HASH)


def decode(source):
	global HASH
	while True:
		key=str(input('Secret key: '))
		if len(key)==0:
			print('Input the key!')
		elif len(key)<KEY_LEN:
			print('The length must be greater than',KEY_LEN,'!')
		else:
			break
	HASH=key

	im=Image.open(source)
	arr = np.array(im)

	time_start=''
	step=0
	for i in range(len(arr)):
		line=arr[i]
		for j in range(len(line)):
			px=line[j]
			r,g,b=px[0],px[1],px[2]
			r=to_bin(r)
			g=to_bin(g)
			b=to_bin(b)
			lr=r[-1]
			lg=g[-1]
			lb=b[-1]
			if len(time_start)<BITS*MARK_LEN:
				time_start+=str(lr)
			else:
				break
			if len(time_start)<BITS*MARK_LEN:
				time_start+=str(lg)
			else:
				step=1
				break
			if len(time_start)<BITS*MARK_LEN:
				time_start+=str(lb)
			else:
				step=2
				break
		if len(time_start)==BITS*MARK_LEN:
			st_i,st_j=i,j
			break

	print('Start mark found!')
	px=arr[st_i][st_j]
	r,g,b=px[0],px[1],px[2]
	r=to_bin(r)
	g=to_bin(g)
	b=to_bin(b)
	lr=r[-1]
	lg=g[-1]
	lb=b[-1]
	mes=''
	if step==0:
		mes+=lr
		mes+=lg
		mes+=lb
	elif step==1:
		mes+=lg
		mes+=lb
	elif step==2:
		mes+=lb

	br=False
	for i in range(len(arr)):
		line=arr[i]
		for j in range(len(line)):
			if i<st_i or i==st_i and j<=st_j:
				pass
			else:
				px=line[j]
				r,g,b=px[0],px[1],px[2]
				r=to_bin(r)
				g=to_bin(g)
				b=to_bin(b)
				lr=r[-1]
				lg=g[-1]
				lb=b[-1]
				mes+=lr+lg+lb
				if time_start in mes:
					br=True
					break
		if br==True:
			break
	print('Finish mark found!')
	mes=mes[:mes.find(time_start)]

	dic=get_dic(time_start+mes)
	if dic==-1:
		print('Wrong key!')
		return

	res=''
	for i in range(len(mes)//BITS):
		byte=mes[:BITS]
		mes=mes[BITS:]
		res+=dic[byte]
	print('Message:',res)


def settings():
	global BITS, KEY_LEN, TIME_SYM, HASH_FUNC
	clear()
	while True:
		print('### SETTINGS ###\n')
		print('All settings will be reset after restart!')
		print('1) Encoding depth:',BITS)
		print('2) Hash function:',HASH_FUNC)
		print('0) Back to menu')
		print()
		ch=str(input('Your choice: '))
		if ch=='1':
			while True:
				try:
					t=int(input('Encoding depth: '))
					if t<1:
						print('Encoding depth must be greater!')
					else:
						BITS=t
						clear()
						break
				except:
					print('Input a number!')
		elif ch=='2':
			while True:
				for i in range(len(HASH_FUNCTIONS)):
					print(str(i+1)+') '+HASH_FUNCTIONS[i])
				try:
					t=int(input('Hash function: '))
					if t<0 or t>len(HASH_FUNCTIONS):
						print('Choice from the list!')
					else:
						HASH_FUNC=HASH_FUNCTIONS[t-1]
						KEY_LEN=len(hashing(HASH_FUNC,'Hello World'))
						clear()
						break
				except Exception as e:
					print(e)
					print('Input a number!')
		elif ch=='0':
			clear()
			return
		else:
			print('No such option!')
			sleep(1)
			clear()


def check_bytes(file):
	f=open(file,'rb')
	data=f.read(100)
	f.close()
	if b'\x89PNG' not in data and file[-(len(file)-2):].lower()=='png':
		print('This is not a PNG file!')
		return 0
	elif b'BM' not in data and file[-(len(file)-2):].lower()=='bmp':
		print('This is not a BMP file!')
		return 0
	else:
		return 1


def check_file(file,must_exist):
	if file.find('.jpg')==len(file)-4 and file.find('.jpg')!=-1:
		print('JPG format is not supported!')
		return 0
	elif file.find('.jpeg')==len(file)-5 and file.find('.jpeg')!=-1:
		print('JPEG format is not supported!')
		return 0
	if file.find('/')!=-1:
		path=file[:file.rfind('/')]
	elif file.find('\\')!=-1:
		path=file[:file.rfind('\\')]
	else:
		path=''
	if os.path.isfile(file):
		if must_exist:
			return (1 if check_bytes(file) else 0)
		else:
			while 1:
				ans=str(input('The file is already exists! Rewrite it?(y/n): ')).lower()
				if ans=='y':
					return 1
				elif ans=='n':
					return 0
				else:
					print('Input y or n!')
	elif os.path.isfile(file)==False and os.path.exists(file):
		print('This is not a file!')
		return 0
	else:
		if must_exist:
			print('No such file!')
			return 0
		else:
			if os.path.exists(path):
				return 1
			else:
				print('No such directory!')
				return 0


def main():
	while True:
		print('### Image Encoder ###\n')
		print('1) Encode')
		print('2) Decode')
		print('3) Settings')
		print('0) Exit\n')
		ch=str(input('Your choice: '))
		if ch=='1':
			while True:
				source=str(input('Source image: '))
				if check_file(source,True):
					break
			while True:
				result=str(input('Result image: '))
				if check_file(result,False):
					break
			while True:
				mes=str(input('Message: '))
				if len(mes)==0:
					print('Type something!')
					continue
				encode(source, result, mes)
				print()
				break
		elif ch=='2':
			while True:
				source=str(input('Image: '))
				if  check_file(source,True):
					break
			while True:
				decode(source)
				print()
				break
		elif ch=='3':
			settings()
		elif ch=='0':
			return -1
		else:
			print('No such option!')
			sleep(1)
			clear()


if __name__=='__main__':
	clear()
	if main()==-1:
		exit()