# Password Manager with 2 secrets key derivation

This password manager uses an encryption key derived from two secrets that the user posses. 

The program is written with python and stores all data in a mysql database, and a secret_key.txt file. 

## Usage
how2


## Master password (MP)

When the user creates a MP, it is hashed with a salt, and is stored in the user table.


## Secret Key (SK)

The secret key is a random key generated with the genrate_random_string method. It is set to 32 characters. This helps secure the vault even if the user's MP is weak. 

The secret key is stored locally on the users machine and is encrypted with a key derived from the MP.


## 2 Secrets Key Derivation (2SKD)
Key derived from secretkey & MP

## Accounts

In this application an account is considered 



## Recovery
When creating account the user is asked to write down their MP.  They are shown their SK once in decrypted format, and asked to write this down aswell.

Both things should stay secret, and only the owner of the vault should know these two secrets, and store them in a safe physical location.


## Known bugs

