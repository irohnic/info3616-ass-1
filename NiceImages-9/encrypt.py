from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from numpy import array

input = open("myfile.png.bin","rb")
print("Opened input file")
dataIn = input.readlines();

maxKeyLength = int(128/8)
key = b'INFO3616INFO3616'

pad_data = lambda data: data + (AES.block_size - len(data) % AES.block_size) * b'0'

cipher = AES.new(key, AES.MODE_ECB)
print(type(dataIn))
a = array(dataIn)
print(a.shape)
encryptedData = cipher.encrypt(pad_data(dataIn))

print("Raw data")
print(dataIn)
print("Encrypted")
print(encryptedData)
input.close()
print("Closed input file")

output = open("myfile.png.bin.enc.bin","wb")
print("Opened output file")

output.close()
print("Closed output file")
