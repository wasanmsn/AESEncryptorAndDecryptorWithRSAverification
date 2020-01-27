# AESEncryptorAndDecryptorWithRSAverification
This program use AES key 256-bit and RSA with key 2048-bit

When run the program first time it will ask for AES key.
You need to Enter the key with 32 chracters and the program will encode your KEY and then create a file name data.txt.enc and will terminate
the program after 14 seconds.
When you open again this time the program will ask you to enter a key for confirmation.
If key is matched.
You will have 5 options to choose -->
 1.select file to encrypt 
 2.select file to decrypt ---* when decrypt a file if the public key is not match with signature.It will not decrypt the file.
 3.select to encrypt every file in directory
 4.select to decrypt every file in directory
 5.exist program
