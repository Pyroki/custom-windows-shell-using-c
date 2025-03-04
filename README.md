# custom-windows-shell-using-c

Secure Windows Shell
A custom Windows shell with cryptographic features such as SHA-256 hashing and XOR-based encryption.

Features
1.Execute Windows shell commands.
2.Encrypt and decrypt files using XOR encryption.
3.Generate SHA-256 hashes for strings and files.

Installation:

Prerequisites
Windows OS
MinGW or Visual Studio for compilation
OpenSSL installed

Build 
gcc myshell.c -o myshell.exe -lws2_32 -lcrypto -lssl

Usage

Command	Description	Example
encrypt <filename>	Encrypts or decrypts a file using XOR encryption.	encrypt secret.txt
hash <string>	Computes the SHA-256 hash of a string.	hash hello
hashfile <filename>	Computes the SHA-256 hash of a file.	hashfile document.txt
exit	Exits the shell.	exit
