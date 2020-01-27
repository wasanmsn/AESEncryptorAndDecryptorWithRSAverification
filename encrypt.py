import codecs
import os
import os.path
import hashlib
from os import listdir
from os.path import isfile, join
import time

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA





class Encryptor:
    def __init__(self, key):
        self.key = key
    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open("pri.txt",'rb') as file:
            pvk = RSA.importKey(file.read())
        with open("pub.txt",'rb') as file:
            pbk = RSA.importKey(file.read())
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        hexify = codecs.getencoder('hex')
        enc = self.encrypt(plaintext, self.key)

        rsa = SHA256.new(enc)
        print("Encode message: ",enc)

        signer = PKCS1_v1_5.new(pvk)
        signature = signer.sign(rsa)
        with open(file_name+"_sig.f",'wb') as file:
            file.write(signature)
        print("HASHED message: ",rsa.hexdigest())
        print("RAW signature : ",signature)

        m = hexify(signature)[0]
        print("Hexify signature: ",m)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        sigfile = file_name[:-4]
        with open("pub.txt",'rb') as file:
            pvk = RSA.importKey(file.read())
        with open(sigfile + "_sig.f", 'rb') as file:
            signature = file.read()
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()

        rsa = SHA256.new(ciphertext)
        signer = PKCS1_v1_5.new(pvk)
        if(signer.verify(rsa,signature) == True) :
            print("Verification success!!")
            dec = self.decrypt(ciphertext, self.key)
            with open(file_name[:-4], 'wb') as fo:
                fo.write(dec)
            os.remove(file_name)
            os.remove(sigfile + "_sig.f")


        else:
            print("Verification failure!!")




    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'encrypt.py' and fname != 'data.txt.enc' and fname != fname+'_sig.f'):
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)



key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
enc = Encryptor(key)
clear = lambda: os.system('cls')

if os.path.isfile('data.txt.enc'):
    while True:
        password = str(input("Enter password: "))
        enc.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            break

    while True:
        clear()
        choice = int(input(
            "1. Press '1' to encrypt file.\n2. Press '2' to decrypt file.\n3. Press '3' to Encrypt all files in the directory.\n4. Press '4' to decrypt all files in the directory.\n5. Press '5' to exit.\n"))
        clear()
        if choice == 1:
            enc.encrypt_file(str(input("Enter name of file to encrypt: ")))
        elif choice == 2:
            enc.decrypt_file(str(input("Enter name of file to decrypt: ")))
        elif choice == 3:
            enc.encrypt_all_files()
        elif choice == 4:
            enc.decrypt_all_files()
        elif choice == 5:
            exit()
        else:
            print("Please select a valid option!")

else:
    while True:
        clear()
        password = str(input("Setting up stuff. Enter a password that will be used for decryption: "))
        repassword = str(input("Confirm password: "))
        if password == repassword:
            break
        else:
            print("Passwords Mismatched!")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encrypt_file("data.txt")
    print("Please restart the program to complete the setup")
    time.sleep(15)



