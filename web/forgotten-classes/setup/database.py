import sqlite3
import hashlib

def hash_password(password):
    md5_hash = hashlib.md5()
    md5_hash.update(password.encode('utf-8'))
    return md5_hash.hexdigest()


class Database: 
    def __init__(self, db_file):
        self.db_file = db_file
        self.connection = None

    # Connect to database
    def connect(self):
            self.connection = sqlite3.connect(self.db_file)

    def disconnect(self):
            if self.connection:
                self.connection.close()
                self.connection = None
    # Commit - After execute
    def commit(self):
        self.connection.commit()

    # Execute a query
    def execute_query(self, query, params=None):
        cursor = self.connection.cursor()
        if params is None:
            cursor.execute(query)
        else:
            cursor.execute(query, params)
        return cursor

    def initialize_database(self):
        self.connect()
        self.execute_query('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        self.commit()
        self.disconnect()
        
    def insert_user(self, data):
        self.connect()
        self.execute_query(''' 
            insert into users (username, password, role) values (:username,:password,:role)
        ''', data)
        self.commit()
        self.disconnect()

    def user_exists(self, data):
        self.connect()
        cursor = self.execute_query(''' 
            select * from users where username=:username
        ''', data)
        rows = cursor.fetchall()
        self.commit()
        self.disconnect()
        return rows

    def login(self, data):
        self.connect()
        cursor = self.execute_query(''' 
            select id,username,role from users where username=:username and password=:password
        ''', data)
        rows = cursor.fetchone()        
        self.commit()
        self.disconnect()
        return rows


db = Database('classroom.db')