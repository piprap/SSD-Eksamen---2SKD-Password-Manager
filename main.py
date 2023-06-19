from dbqueries import *
from cryptography.fernet import Fernet
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

import os, base64

def main():

    running = True
    user_id = ''

    while running == True:
        print('\nPress 1. to login \nPress 2. to register \nPress 3. to exit')
        choice = int(input("Choose an option: "))

        if choice == 1:

            #Initialize user data from login
            user_data = login()
            connected = user_data[0]
            user_id = user_data[1]
            accounts = user_data[2] 


            #
            while connected == True:
                print('\nPress 1. to add service \nPress 2. to list services \nPress 3. to logout')
                authenticated_choice = int(input("Choose an option: "))

                if authenticated_choice == 1:
                    addPassword(user_id)
                    #Update passwords associated with user_id including new entry
                    accounts = getAccounts(user_id)

                elif authenticated_choice == 2:
                    decrypt_password(accounts)

                elif authenticated_choice == 3:
                    #clears all previous user information
                    user_data = tuple()
                    connected = False
                    user_id = ''
                    accounts = tuple()

        elif choice == 2:
            signup()
        elif choice == 3:
            running = False
    


def signup():

    email = input("Enter email: ")

    #Get User MP
    master_password = getpass.getpass("Enter your master password: ") # Using getpass to safely get masterpassword input from terminal
    password_salt = bcrypt.gensalt() #generating salt with bcrypt function
    hashed_password = bcrypt.hashpw(master_password.encode("utf-8"), password_salt) # Hash PW & salt to avoid rainbowtables 

    print('write down your masterpassword on piece of paper')
    input("You are about to generate your secret key - This should not be shown to anyone - Enter to continue...")

    #GenerateSecretKey with 32 random chars.
    secret_key = generate_random_string(32)
    print("SECRET KEY: ", secret_key)

    print('Write down your secret key and store it safely with your masterpassword. Preferably in a bank box.')
    print('Your secret key will also be saved to folder of your password manager. DO NOT DELETE OR SHARE YOUR SECRET KEY')
    print('Your secret key is used in combination with your Master Password to access the rest of your passwords in the vualt')
    
    #Write ENCODED secret key to file: 
    salt = generate_salt()
    
    #encode secret key with masterpassword
    encrypted_secret_key = encrypt_secret_key(secret_key, master_password, salt, 'secret_key.txt')

    #DB Func
    createUser(email, hashed_password, password_salt)
    return


def login():
    
    email = input(f"\nEnter your email: ")
    
    #Get MP & SALT
    results = getUserPWHash(email)  # Replace with the stored hashed password
    stored_hashed_password = results[0] #decode("utf-8")
    salt = results[1]

    #Get MP
    master_password = getpass.getpass("Enter your master password: ") # Using getpass to safely get masterpassword input from terminal
    hashed_password = bcrypt.hashpw(master_password.encode("utf-8"), salt.encode("utf-8")) # Hash PW & salt to avoid rainbowtables 

    # Compare the stored hashed password with the provided password
    if bcrypt.checkpw(master_password.encode("utf-8"), stored_hashed_password.encode("utf-8")):
        print(f"Password is correct! - Welcome {email}")
        #Get accounts
        user_id = getUserId(email) #SKAL FIXES

        #Decrypt secret-key file with MP 

        #Get passwords associated with user_id
        accounts = getAccounts(user_id)

        
        #decrypt secret key:
        decrypted_secret_key = decrypt_secret_key(master_password, 'secret_key.txt')

        return True, user_id, accounts

    else:
        print("Email or password is incorrect! Try again")
        login()

def encrypt_password(vault_password, two_secrets_key):

    cipher = AES.new(two_secrets_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(vault_password.encode())
    
    return ciphertext, cipher.nonce, tag

def decrypt_password(accounts):
    
    #List all accounts by service name:
    print(f"\nList of all services you have a stored password for:") 
    for service in accounts:
        print(" - ", service[2])
    

    #Select password that will be decrypted.
    selected_service = input("Enter the service name (case sensitive) or exit to quit: ")
    if selected_service == "exit":
        return
    else:
        for service in accounts:
            if service[2] == selected_service:
                #get MP
                master_password = getpass.getpass(f"Enter your master password to decrypt password for {selected_service}: ") # Using getpass to safely get masterpassword input from terminal

                #get decrypted secret key
                decrypted_secret_key = decrypt_secret_key(master_password, 'secret_key.txt')
                
                #Initialize variables used to decrypt 
                ciphertext = service[3]
                encryption_password_salt = service[4] 
                tag = service[5]
                nonce = service[6]

                two_secrets_key = derive_key(master_password + decrypted_secret_key, encryption_password_salt)

                cipher = AES.new(two_secrets_key, AES.MODE_EAX, nonce)
                secret_key = cipher.decrypt_and_verify(ciphertext, tag).decode()

                print(f"The password for {selected_service} is {secret_key} \n")
                return
        print("Account not found")

    return

def encrypt_secret_key(secret_key, master_password, salt, file_path):
    key = derive_key(master_password, salt)

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(secret_key.encode())

    with open(file_path, 'wb') as file:
        file.write(salt)
        file.write(cipher.nonce)
        file.write(tag)
        file.write(ciphertext)
    return ciphertext

def decrypt_secret_key(master_password, file_path):
    with open(file_path, 'rb') as file:
        salt = file.read(16)
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()

    key = derive_key(master_password, salt)

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    secret_key = cipher.decrypt_and_verify(ciphertext, tag)

    return secret_key.decode()


# Generate a random salt of 16 bytes
def generate_salt():
    return os.urandom(16)

# Derive key from the master password & sometimes secret key combined.
def derive_key(master_password, salt):
    key = PBKDF2(master_password, salt, dkLen=32, count=100000)  # 32-byte key
    return key


def addPassword(user_id):
    #get service
    service = input(f"\nEnter service name: ")
    #get pw
    vault_password = getpass.getpass(f"Enter the password for {service}: ") # Using getpass to safely get masterpassword input from terminal

    #get MP
    master_password = getpass.getpass("Enter your master password: ") # Using getpass to safely get masterpassword input from terminal
    
    #get decrypted secret key
    decrypted_secret_key = decrypt_secret_key(master_password, 'secret_key.txt')

    #Generate salt
    encryption_password_salt = generate_salt()

    # 2 Secret Key Derivation
    two_secrets_key = derive_key(master_password + decrypted_secret_key, encryption_password_salt)

    #encrypt password:
    encryption_variables = encrypt_password(vault_password, two_secrets_key)
    
    encrypted_password = encryption_variables[0]
    nonce = encryption_variables[1]
    authentication_tag = encryption_variables[2]

    createAccount(user_id, service, encrypted_password, encryption_password_salt, authentication_tag, nonce)
    return

def generate_random_string(length=12):

    # string.ascii_letters = abcdefghijklmnopqrstuvwxyz - upper & lower case.
    # string.digits        = 0123456789
    # string.punctuation   = !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~.
    chars = string.ascii_letters + string.digits + string.punctuation

    return ''.join(random.choice(chars) for _ in range(length)) # Returns a string consisting of length amount of random chars from the chars string

main()

