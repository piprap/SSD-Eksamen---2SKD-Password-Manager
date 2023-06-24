import getpass, string, random
import bcrypt
from db_connection import get_database_connection


def createUser(email, hashed_password, password_salt, twofactor_secret_key, twofactor_status):
    conn = get_database_connection()
    cursor = conn.cursor(prepared=True)

    try:
        query = "INSERT INTO users (email, master_password, password_salt, twofactor_secret_key, twofactor_status) VALUES (?, ?, ?, ?, ?)"
        values = (email, hashed_password, password_salt, twofactor_secret_key, twofactor_status)
        
        cursor.execute(query, values)
        conn.commit()
        print("User created with email: ", email)
    except:
        print("An error occurred:")    
    
    cursor.close()
    conn.close()

def createAccount(user_id, service, encrypted_password, salt, authentication_tag, nonce):
    conn = get_database_connection()
    cursor = conn.cursor(prepared=True)

    query = "INSERT INTO passwords (user_id, service, encrypted_password, encryption_password_salt, authentication_tag, nonce) VALUES (?, ?, ?, ?, ?, ?)"
    values = (user_id, service, encrypted_password, salt, authentication_tag, nonce)
    
    cursor.execute(query, values)
    conn.commit()
    
    cursor.close()
    conn.close()

    print(f'Password added for {service} \n')

    return

def getUserId(email):
    conn = get_database_connection()
    cursor = conn.cursor(prepared=True)

    query = "SELECT * FROM users WHERE email = ?"
    values = (email,)
    
    cursor.execute(query, values)
    result = cursor.fetchone()
    
    cursor.close()
    conn.close()
    return result[0]

def getUserPWHash(email): #should be renamed or split into two functions.
    conn = get_database_connection()
    cursor = conn.cursor(prepared=True)

    query = "SELECT master_password, password_salt, twofactor_secret_key, twofactor_status FROM users WHERE email = ?"
    values = (email,)
    
    cursor.execute(query, values)
    result = cursor.fetchone()
    
    cursor.close()
    conn.close()
    return result

def getAccounts(user_id):
    conn = get_database_connection()
    cursor = conn.cursor(prepared=True)
    
    query = "SELECT * FROM passwords WHERE user_id = ?"
    values = (user_id,)
    
    cursor.execute(query, values)
    result = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return result