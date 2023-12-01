 ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## 
##
##	AES.py
##
##
##
##
##	This program is an implementation of AES encryption / decryption 
##  making use of the python module PyCrypto. 
##
##

## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## 
## Author: Dawson Burgess
## Version: 1.0xx
## Date: 12/1/23
##
## You are free to use, change, or redistribute the code in any way
## you wish for non-commercial purposes, but please maintain the name
## of the original author. This code is not guaranteed to function
## correctly and comes with no warranty of any kind for any purpose
## what-so-ever and is NOT SUPPORTED.   Good luck and have fun.

## IMPORTANT
##

##
## [warnings]
##
##
##
## [other info]
##
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import os.path



class AES_Encryptor:
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
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

def generate_key(key_location):
    # generating a key
    key = get_random_bytes(32) # this will be for 256 bit, 1 byte = 8 bit, 8 * 32 = 256 bit

    #storing the generated key 
    file_out = open(key_location, 'wb') # wb = write bytes
    file_out.write(key)
    file_out.close()


def select_key(key_location):
    file_in = open(key_location, 'rb') # rb = read bytes
    key = file_in.read() # read key from file
    file_in.close()

    return key 


def main():

    while True:
        key_selection = int(input("1. Enter '1' to generate a 256 bit key.\n2. Enter '2' to select a key from a file or thumbdrive.\n3. Enter '3' to exit\n")) 
    	#key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
    	#enc = AES_Encryptor(key)
        if key_selection == 1:
            storage_location = (str(input("Enter name of where you would like to store the generated key: ")))
            generate_key(storage_location)
        elif key_selection == 2:
            retrieve_key = (str(input("Enter name of where your key is stored: ")))
            key = select_key(retrieve_key)
            break
        elif key_selection == 3:
            exit()

    enc = AES_Encryptor(key)
    while True:
        user_input = int(input(
            "1. Enter '1' to encrypt file.\n2. Enter '2' to decrypt file.\n3. Enter '3' to exit.\n"))
        if user_input == 1:
            enc.encrypt_file(str(input("Enter name of file to encrypt: ")))
        elif user_input == 2:
            enc.decrypt_file(str(input("Enter name of file to decrypt: ")))
        elif user_input == 3:
            exit()
        else:
            print("Please enter a valid option.")


if __name__ == "__main__":
	main()