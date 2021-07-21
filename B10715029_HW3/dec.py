from typing import List, Tuple
from PIL import Image
from Crypto.Cipher import AES
import numpy as np
import sys, os

def imgToBytes(path:str, maxLen:int=16) -> Tuple[int, int, List[bytes]]:
	retBytes = []

	img = Image.open(path)
	imgArray = np.asarray(img)

	imgH, imgW = img.height, img.width
	temp = []
	for i in range(imgH):
		for j in range(imgW):
			pixel = imgArray[i,j]
			for c in range(len(pixel)):
				temp.append(pixel[c])

			if(len(temp) >= maxLen):
				seg = temp[:maxLen]
				retBytes.append(bytes(seg))
				temp = temp[maxLen:]

	if(len(temp) != 0):
		while(len(temp) < maxLen):
			temp.append(0) # pad 0 at tail

		retBytes.append(bytes(temp))
		temp.clear()
	return (imgH, imgW, retBytes)

def _bytesToNpArray(data:List[bytes], height:int, width:int) -> np.ndarray:
	imgData = np.ndarray((height, width, 3), dtype=np.uint8)
	h = 0
	w = 0
	ch = 0
	end = False
	for segment in data:
		for byte in segment:
			imgData[h,w,ch] = byte
			ch += 1
			if(ch >= 3):
				w += 1
				ch = 0
			if(w >= width):
				h += 1
				w = 0
			if(h >= height):
				end = True
				break
		if(end):
			break
	return imgData

def bytesToPng(path:str, data:List[bytes], height:int, width:int) -> np.ndarray:
	imgArray = _bytesToNpArray(data, height, width)
	img = Image.fromarray(imgArray)
	img.save(path, "png")
	return imgArray


def _AESEncBlock(plain: bytes, key: bytes) -> bytes:
	assert(len(plain) == 16)
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(plain)
def _AESDecBlock(c: bytes, key: bytes) -> bytes:
	assert(len(c) == 16)
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.decrypt(c)
def ECB_decrypt(cipherData:List[bytes], key:bytes) -> List[bytes]:
	plainData = []
	for segment in cipherData:
		plainData.append(_AESDecBlock(segment, key))
	return plainData
def CTR_decrypt(cipherData:List[bytes], key:bytes, iv:bytes) -> List[bytes]:
	plainData = []
	for segment in cipherData:
		civ = _AESEncBlock(iv, key)
		plainSeg = bytes([b1 ^ b2 for b1, b2 in zip(segment, civ)])
		plainData.append(plainSeg)
		iv = (int.from_bytes(iv, "big") + 1).to_bytes(16, "big")  # iv += 1
	return plainData
def PCBC_decrypt(cipherData:List[bytes], key:bytes, iv:bytes) -> List[bytes]:
	plainData = []
	for segment in cipherData:
		pxiv = _AESDecBlock(segment, key)
		plainSeg = bytes([b1 ^ b2 for b1, b2 in zip(pxiv, iv)])
		plainData.append(plainSeg)
		iv = bytes([b1 ^ b2 for b1, b2 in zip(segment, plainSeg)])
	return plainData

def main():
	mode = "Custom"
	key = b'\xd5\x07V\x148\xd4\xa78r\xf5\x05\x8a\xad\xf2}]'
	iv = b'\xa8\xf4\x07t\x83j,\xceK^\x97/\xb2\x1c\x16\xec'

	for i in range(1, len(sys.argv)):
		if sys.argv[i] == '--iv':
			i = i + 1
			#check if the iv and key length is correct
			if len(sys.argv[i]) == AES.block_size:
				iv = str.encode(sys.argv[i])          
		elif sys.argv[i] == '--key':
			i = i + 1
			if len(sys.argv[i]) == AES.block_size:
				key = str.encode(sys.argv[i])
		elif sys.argv[i] == "--mode":
			i += 1
			mode = sys.argv[i]

	imgPath = "./test_enc/" + mode + ".png"
	savePath = "./test_dec/" + mode + ".png"

	height, width, data = imgToBytes(imgPath, maxLen=16)
	if(mode == "ECB"):
		dataDec = ECB_decrypt(data, key)
	elif(mode == "CTR"):
		dataDec = CTR_decrypt(data, key, iv)
	elif(mode == "Custom"):
		dataDec = PCBC_decrypt(data, key, iv)

	if(not os.path.exists('./test_dec')):
		os.makedirs('./test_dec')

	bytesToPng(savePath, dataDec, height, width)

if __name__ == "__main__":
	main()
