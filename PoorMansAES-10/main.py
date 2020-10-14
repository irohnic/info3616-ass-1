import os
import sys
import binascii
from Crypto.Cipher import AES

plain1 = "################".encode()
plain2 = "#              #".encode()
plain3 = "#    START     #".encode()
plainX = "#     END      #".encode()
plainStart = [plain1, plain2, plain3, plain2, plain1]
plainEnd = [plain1, plain2, plainX, plain2, plain1]
key = 'INFO3616INFO3616'.encode() # I am not about to tell you!

cipher = AES.new(key, AES.MODE_ECB)


def run_xor(b1, b2):
    if len(b1) != len(b2):
        print("XOR: mismatching length of byte arrays")
        os.exit(-1)

    output = []

    for i in range(0, len(b1)):
        x = b1[i] ^ b2[i]
        t = "%x" % x
        if len(t) == 1:
            t = "0" + t
        output.append(t)
    return "".join(output)



def transcrypt(nonce, input_text):

    enc_nonce = cipher.encrypt(nonce)
    ciphertext = run_xor(enc_nonce, input_text)
    return ciphertext



def encrypt_input_file(filename):
    with open(filename, "r") as infh, open("encrypted.enc", "w") as outfh:
        i = 0
        for line in infh:
            line = line.rstrip("\n")
            nonce = "000000000000000" + str(i)
            res = transcrypt(nonce.encode(), line.encode())
            outfh.write(str(i) + "," + res + "\n")
            i = (i + 1) % 10


def break_input_file(filename):

      #Define arbitrary number based on nonce modulus generation
    nBlocks = 10

    #Read input file
    infh = open(filename,"r").readlines()

    #Declare variables for storing data, pointers, and keys
    matched = [[0 for x in range(int(len(infh)/nBlocks))] for y in range(nBlocks)]
    pointers = [0 for x in range(len(matched))]
    encryptedNonces = [0 for x in range(len(matched))]

    i = 0
    for line in infh:
        firstChar = int(line[0])
        line = binascii.unhexlify(line.rstrip("\n")[2:]) #Clean input and format as bytes
        matched[firstChar][pointers[firstChar]] = line #Store in blocks based on line number
        pointers[firstChar] = pointers[firstChar]+1 #Update block line pointer
        i = (i + 1) % nBlocks

    #Find the nonce encryption key for the first n/2 lines (given known start)
    for i in range(int(nBlocks/2)):
        nonce = "000000000000000" + str(i)
        encryptedNonces[i] = binascii.unhexlify(run_xor(matched[i][0],plainStart[i])) #Find encrypted nonce using xor 'reversal' of known input and encrypted output
        #print("Key " + str(i) + " :" + str(encryptedNonces[i]))

    #Find the nonce encryption key for the final n/2 lines (given known end)
    for i in range(int(nBlocks/2)):
        nonce = "000000000000000" + str(i+int(nBlocks/2))
        encryptedNonces[i+int(nBlocks/2)] = binascii.unhexlify(run_xor(matched[i+int(nBlocks/2)][int(len(infh)/nBlocks)-1],plainEnd[i])) #Find encrypted nonce using xor 'reversal' of known input and encrypted output
        #print("Key " + str(i+5) + " :" + str(encryptedNonces[i+5]))

    #Decrypt lines using appropriate keys
    for i in range(len(matched)):
        for j in range(len(matched[i])):
            matched[i][j] = binascii.unhexlify(run_xor(encryptedNonces[i],matched[i][j])).decode() #Find unencrypted input using xor 'reversal' of encrypted out and encrypted nonce
            #print("UN: " + matched[i][j])

    #Print the decrypted lines in order, and to file
    outfh = open("unencrypted.enc", "w")
    for j in range(len(matched[0])):
        for i in range(len(matched)):
            outfh.write(matched[i][j] + "\n")
            print(matched[i][j])

    pass


def main(args):
    if len(args) > 1:
        filename = args[1]
        break_input_file(filename)
    else:
        print("Please provide an file to break!")

if __name__ == '__main__':
    main(sys.argv)
