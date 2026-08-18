import mysql.connector

def get_connection():
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password='YOUR_MYSQL_PASSWORD'
        database="phishguard_db"
    )

    return connection
