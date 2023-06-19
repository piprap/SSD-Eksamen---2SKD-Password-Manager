# Password Manager with 2 secrets key derivation

This password manager uses an encryption key derived from two secrets that the user posses. 



--- 
## Usage
how2

---
## Master password (MP)

explain

---
## Secret Key (SK)

The secret key is a random key generated with the genrate_random_string method. It is set to 32 characters. This helps secure the vault even if the user's MP is weak. 

The secret key is stored locally on the users machine and is encrypted with a key derived from the MP.

---
## 2 Secrets Key Derivation (2SKD)
Key derived from secretkey & MP

## Accounts

Interface/structure 

---

## Recovery
When creating account make emergency kit

---
## Known bugs

