from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from binascii import unhexlify

block_length = 16

class Principal:

    # key_length: RSA key length this principal will use
    # name: name of principal, save key under "name".der in DER format
    def __init__(self, key_length, name):
        # YOUR TASK STARTS HERE
        self.own_key = self.create_rsa_key(key_length)
        # YOUR TASK ENDS HERE
        with open("{}.der".format(name), "wb") as out_fh:
            out_fh.write(self.own_key.exportKey(format ='DER', pkcs=1))

    # Create RSA key of given key_length
    def create_rsa_key(self, key_length):
        # YOUR TASK STARTS HERE
        rsa_keypair = RSA.generate(key_length)
        # YOUR TASK ENDS HERE
        return rsa_keypair

    # Return public key part of public/private key pair
    def get_public_key(self):
        # YOUR TASK STARTS HERE
        # ...
        # YOUR TASK ENDS HERE
        public_key = self.own_key.publickey()
        return public_key

    # Receiving means reading an hybrid-encrypted message from a file.
    # Returns: encrypted key (bytes), encrypted message (bytes), IV (bytes),
    # number of padding bytes
    def receive(self, filename):
        # YOUR TASK STARTS HERE
        # Read lines from file
        f = open(filename, 'r')
        lines = f.readlines()
        f.close()

        # Remove new lines
        i = 0
        for line in lines:
            line = line.strip("\n")
            lines[i] = line
            i += 1

        # Assign to each variable
        ck_hex, cm_hex, iv_hex, pad_len_string = lines
        ck_bytes = unhexlify(ck_hex)
        cm_bytes = unhexlify(cm_hex)
        iv_bytes = unhexlify(iv_hex)
        pad_len_int = int(pad_len_string)

        # YOUR TASK ENDS HERE
        return [ck_bytes, cm_bytes, iv_bytes, pad_len_int]

    # Sending means writing an encrypted message plus metadata to a file.
    # Line 1: RSA-encrypted symmetric key, as hex string.
    # Line 2: Symmetrically encrypted message, as hex string.
    # Line 3: IV as hex string
    # Line 4: Number of padding bytes (string of int)
    def send(self, filename, msg):
        # YOUR TASK STARTS HEREsym_key, enc_msg, iv, padding = msg
        sym_key, enc_msg, iv, padding = msg
        hex_sym_key = sym_key.hex()
        hex_enc_msg = enc_msg.hex()
        hex_iv = iv.hex()
        hex_padding = str(padding)

        full_msg = hex_sym_key + "\n" + hex_enc_msg + "\n" + hex_iv + "\n" + hex_padding

        f = open(filename, 'w')
        f.write(full_msg)
        f.close()

        # YOUR TASK ENDS HERE
        pass

# Hybrid Cipher encapsulates the functionality of a hybrid cipher using
# RSA and AES-CBC.
# Key length of AES is a parameter.
class HybridCipher:

    # length_sym: length of symmetric key. Must be 128, 192, or 256.
    # own_key: public/private key pair of owner (principal who can decrypt)
    # remote_pub_key: public key of principal this hybrid cipher is encrypting to
    def __init__(self, length_sym, own_key, remote_pub_key):
        # YOUR TASK STARTS HERE
        self.length_sym = length_sym
        self.own_key = own_key
        self.remote_pub_key = remote_pub_key
        # YOUR TASK ENDS HERE
        pass


    # Creates an AES cipher in CBC mode with random IV, and random key
    # Returns: cipher, IV, symmetric key
    def create_aes_cipher(self, length):
        # YOUR TASK STARTS HERE
        iv = Random.get_random_bytes(16)
        sym_key = Random.get_random_bytes(length)
        cipher = AES.new(sym_key, AES.MODE_CBC,iv)
        # YOUR TASK ENDS HERE
        return cipher, iv, sym_key


    # Decrypted hybrid-encrypted msg
    # Returns: decrypted message with padding removed, as string
    def decrypt(self, msg):
        # YOUR TASK STARTS HERE
        ck, cm, iv, pad_len = msg

        cipher2 = PKCS1_OAEP.new(self.own_key)
        sym_key = cipher2.decrypt(ck)
        cipher = AES.new(sym_key, AES.MODE_CBC, iv)

        rcvd_msg_dec = cipher.decrypt(cm)
        rcvd_msg_dec = rcvd_msg_dec.decode()
        rcvd_msg_dec = self.strip_pad(rcvd_msg_dec,pad_len)
        

        # YOUR TASK ENDS HERE
        return rcvd_msg_dec


    # Encrypts plaintext message to encrypt in hybrid fashion.
    # Returns: encrypted symmetric key, encrypted message, IV, number of padding bytes
    def encrypt(self, msg):
        # YOUR TASK STARTS HERE

        padded_msg, pad_len = self.pad(msg.encode())
        cipher, iv, sym_key = self.create_aes_cipher(self.length_sym)
        cm = cipher.encrypt(padded_msg)
        cipher2 = PKCS1_OAEP.new(self.remote_pub_key)
        ck = cipher2.encrypt(sym_key)

        # YOUR TASK ENDS HERE
        return [ck, cm, iv, pad_len]

    # Padding for AES-CBC.
    # Pad up to multiple of block length by adding 0s (as byte)
    # Returns: padded message, number of padding bytes
    def pad(self, msg):
        # YOUR TASK STARTS HERE

        # Calculate how many padding bytes required
        padded_msg = msg
        padding_required = block_length - (len(msg) % block_length)

        # Add padding bytes
        i = 0
        while i < padding_required:
            padded_msg += b'0'
            i += 1

        # YOUR TASK ENDS HERE
        return padded_msg, padding_required

    # Strips padding and converts message to str.
    def strip_pad(self, msg, pad_len_int):
        # YOUR TASK STARTS HERE
        msg_unpadded = str(msg[:(len(msg)-pad_len_int)])
        # YOUR TASK ENDS HERE
        return msg_unpadded




def main():
    # We create Alice as a principal. In this example, we choose a
    # 2048 bit RSA key.
    alice = Principal(2048, "alice")
    # We create Bob as a principal.
    bob = Principal(2048, "bob")

    # We create a HybridCipher for Alice to use. She uses Bob's public key
    # because he is the receiver. Her own public/private key pair goes in there, too,
    # for completeness.
    a_hybrid_cipher = HybridCipher(16, alice.own_key, bob.get_public_key())

    # Alice has a message for Bob.
    msg = "Hi Bob, it's Alice."
    # Alice uses the hybrid cipher to encrypt to Bob.
    msg_enc = a_hybrid_cipher.encrypt(msg)
    alice.send("msg.enc", msg_enc)

    # Bob receives
    rcv_msg_enc = bob.receive("msg.enc")
    # Bob creates a HybridCipher. He configures it with his own public/private
    # key pair, and Alice's public key for completeness.
    b_hybrid_cipher = HybridCipher(128, bob.own_key, alice.get_public_key())
    # Bob decrypts.
    dec_msg = b_hybrid_cipher.decrypt(rcv_msg_enc)
    print(dec_msg)
    
    if msg == dec_msg:
        print("This worked!")

main()
