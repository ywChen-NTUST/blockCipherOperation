from PIL import Image
from Crypto.Cipher import AES
from Crypto import Random
import io, os, sys

#get random iv, key of block size
iv = Random.new().read(AES.block_size)
key = Random.new().read(AES.block_size)

#or get iv, key from user
for i in range(1, len(sys.argv)):
	if sys.argv[i] == '-iv':
		i = i + 1
		#check if the iv and key length is correct
		if len(sys.argv[i]) == AES.block_size:
			iv = str.encode(sys.argv[i])          
	elif sys.argv[i] == '-key':
		i = i + 1
		if len(sys.argv[i]) == AES.block_size:
			key = str.encode(sys.argv[i])

#read input image
im = Image.open('./linux.jpeg')
#save image as ppm format temporary
im.save('./tmp.ppm', 'ppm')

#create a new AES cipher 
cipher = AES.new(key, AES.MODE_ECB)

block = bytes()

def xor(lhs, rhs):
	return bytes(a ^ b for a, b in zip(lhs, rhs))

with open('./tmp.ppm', 'rb') as image:
	#read some bytes as header, no encryping will be done. 
	#not sure if the header should be 15 bytes or ...
	result_ecb = image.read(15) 
	result_ctr = result_ecb[:-1] + result_ecb[-1:]
	result_cus = result_ecb[:-1] + result_ecb[-1:]
	iv_custom = iv[:-1] + iv[-1:]
	block = image.read(AES.block_size)
	while block:     
		#padding null if length < block size  
		if (len(block) < AES.block_size): 
			block = block.ljust(AES.block_size, b'\0')
		#ecb encrypt
		result_ecb += cipher.encrypt(block) 
		#ctr encrypt
		chipher_iv = cipher.encrypt(iv)
		result_ctr += xor(block, chipher_iv)
		iv = (int.from_bytes(iv, 'big') + 1).to_bytes(AES.block_size, 'big')
		#custom encrypt (pcbc)
		tmp = cipher.encrypt(xor(iv_custom, block))
		result_cus += tmp
		iv_custom = xor(tmp, block)
		#read next block
		block = image.read(AES.block_size)

#save the result as png (to avoid losing due to jpeg compression)
if not os.path.exists('./test_enc'):
	os.makedirs('./test_enc')
Image.open(io.BytesIO(result_ecb)).save('./test_enc/ECB.png', 'png')
Image.open(io.BytesIO(result_ctr)).save('./test_enc/CTR.png', 'png')
Image.open(io.BytesIO(result_cus)).save('./test_enc/Custom.png', 'png')
#remove temporary ppm file
os.remove('tmp.ppm')
