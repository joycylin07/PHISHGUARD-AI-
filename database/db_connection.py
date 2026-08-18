import mysql.connector

def get_connection():
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="system",
        database="phishguard_db"
    )

    return connection
