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
key = "INFO3616INFO3616" # I am not about to tell you!

cipher = AES.new(key, AES.MODE_ECB)


def run_xor(b1, b2):
    if len(b1) != len(b2):
        print("XOR: mismatching length of byte arrays")
        os.exit(-1)

    output = []

    for i in range(0, len(b1)):
        x = b1[i] ^ b2[i]
        t = "%x" % x #convert decimal to hex

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
    emptyByte = b'\x00'
    emptyStream = emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte + emptyByte
    #print(emptyStream)

    nonce = "0000000000000000"
    enc_nonce = cipher.encrypt(nonce.encode())
    print("Encrypted nonce: ",enc_nonce)
    data = "this is a tet!@#"
    print("Data: ",data)
    #encoded_data = run_xor(enc_nonce,data.encode())
    encoded_data = "4057562b7defa5579e65a89c7d75be51"
    #encoded_data = "70e0e190d80210e37527246b67e7d488"
    print("encoded unhexed: ", encoded_data)
    enc_data = binascii.unhexlify(encoded_data)
    print("Encrypted Data: ", enc_data)


    unenc_data = binascii.unhexlify(run_xor(enc_nonce,enc_data))
    print("Unencrypted Data: ",unenc_data)

    with open(filename, "r") as infh, open("unencrypted.enc", "w") as outfh:
        i = 0
        for line in infh:
            line = line.rstrip("\n")[2:]
        #    print(line)
            line = binascii.unhexlify(line)
            print("-----------------")
            print(line)

            nonce = "000000000000000" + str(i)

            enc_nonce =
            #enc_nonce = cipher.encrypt(nonce.encode())

            res = binascii.unhexlify(run_xor(enc_nonce,line))

            print(res)

            #outfh.write(str(i) + "," + res + "\n")
            i = (i + 1) % 10


    #print(enc_nonce)
    # plain = "abcdefghijklmnop"
    # print(plain)
    # encrypted = transcrypt(nonce.encode(), plain.encode());
    # #THIS IS WHAT WE TRY TO DECODE
    # print(encrypted)
    #
    # encryptionOut = run_xor(enc_nonce,emptyStream)
    # print(encryptionOut)
    # print(run_xor(encrypted.encode(),encryptionOut.encode()))

    pass


def main(args):
    if len(args) > 1:
        filename = args[1]
        break_input_file(filename)
    else:
        print("Please provide an file to break!")

if __name__ == '__main__':
    main(sys.argv)
