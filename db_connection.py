import mysql.connector
import os
from dotenv import load_dotenv


load_dotenv()

userEnv = os.getenv('DATABASE_USER')
passwd = os.getenv('DATABASE_PASSWORD')
database = os.getenv('DATABASE_NAME')

def get_database_connection():
    return mysql.connector.connect(
        host="localhost",
        user=userEnv,
        passwd=passwd,
        database=database
    )
