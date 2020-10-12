from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#This function takes data read from file, and pads it to an integer multiple of the
#AES blocksize
def pad_list(data):
    requiredFill = (AES.block_size - len(data[0])) % AES.block_size
    for _ in range(requiredFill):
        data[0] = data[0] + b'0'
    return(data[0])

#Open, read, and close input file
input = open("myfile.png.bin","rb")
print("Opened input file")
dataIn = input.readlines();
input.close()
print("Closed input file")

#Define encryption key
key = b'INFO3616INFO3616'
#Generate cipher object using key
cipher = AES.new(key, AES.MODE_ECB)
#Pad data
paddedData = pad_list(dataIn)
#Encrypt data
encryptedData = cipher.encrypt(paddedData)

#Open, write, and close output file
output = open("myfile.png.bin.enc.bin","wb")
print("Opened output file")
output.write(encryptedData)
output.close()
print("Closed output file")
