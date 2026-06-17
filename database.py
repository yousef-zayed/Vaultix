import sqlite3


class Database:
    def __init__(self):
        ## create the connection and the cursor variables to start execution
        self.db = sqlite3.connect("vaultix.db")
        self.exe = self.db.cursor()
        self.init_db()


    def init_db(self):
        '''
        creates the user table and the passwords table if they don't exist
        '''       
        ## creates the database tables if doesn't exist 
        self.exe.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site TEXT NOT NULL,
                username TEXT,
                encrypted_password BLOB NOT NULL,
                nonce BLOB,
                tag BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)

        self.db.commit()

    
    def close(self):
        self.db.close() ## closes the database and no longer accessible until new connection


    def get_user(self, username:str) -> tuple:
        '''
        gets the user id and salt

        :param username: the user's username
        :type username: str
        :return: a tuple containing the username and salt, if nothing found returns None
        :rtype: tuple
        '''
        return self.exe.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()


    def add_user(self, username:str, salt:str):
        '''
        adds a new user to the database

        :param username: the user's username
        :type username: str
        :param salt: the user's salt
        :type salt: str
        :raise sqlite3.IntegrityError: if there's already a user with the same username
        '''
        self.exe.execute("INSERT INTO users (username, salt) VALUES (?, ?);", (username, salt))
        self.db.commit()


    def delete_user(self, username:str) -> bool:
        '''
        deletes a specific user given his username

        :param username: the user's username
        :type username: str
        :return: True if the user has been found and the deletion was successful otherwise False
        :rtype: bool
        '''
        self.exe.execute("DELETE FROM users WHERE (username = ?);", (username,))
        if not self.exe.rowcount:
            return False ## No matching user
        else:
            self.db.commit()
            return True

    
    def get_password(self, username:str, service:str, user:int) -> tuple:
        '''
        retrives the password of a specific service of a certain user

        :param username: the service account's username
        :type username: str
        :param service: the desired service/website of the account
        :type service: str
        :parm user: the user's id
        :type user: int
        :return: the encrypted password of the account, if no such record meeting all the parameters returns None
        :rtype: tuple
        '''
        return self.exe.execute('''SELECT encrypted_password, nonce, tag FROM passwords 
                                  WHERE (username = ? AND site = ? AND user_id = ?)'''
                                  , (username, service, user)).fetchone()
        

    def get_all_passwords(self, user:int) -> tuple:
        '''
        retrives all the password of a certain user

        :param user: the user's id
        :type use: int
        :return: tuple containing all the entries of the user
        :rtype: tuple
        '''
        return self.exe.execute('''SELECT site, username, encrypted_password, nonce, tag FROM passwords
                                WHERE user_id = ?;''', (user,)).fetchall()
        
    
    def add_password(self, username:str, pswd:bytes, service:str, user:int, nonce:bytes, tag:bytes):
        '''
        adds a new record in the passwords table

        :param username: the username of the account
        :type username: str
        :param pswd: the encrypted password of the account
        :type pswd: bytes
        :param servcie: the website/service of the account
        :type service: str
        :param user: the user's id
        :type user: int
        :param nonce: the number used once of the encrypted password so it can be used to decrypt it
        :type nonce: bytes
        :param tag: the authentication block of the password, verifies if it has been altered or not
        :type tag: bytes
        '''
        self.exe.execute('''INSERT INTO passwords (user_id, site, username, encrypted_password, nonce, tag)
                            VALUES (?, ?, ?, ?, ?, ?);''', (user, service, username, pswd, nonce, tag))
        self.db.commit()


    def update_password(self, username:str, pswd:bytes, service:str, user:int, nonce:bytes, tag:bytes):
        '''
        update an existing record in the passwords table

        :param username: the username of the account
        :type username: str
        :param pswd: the encrypted password of the account
        :type pswd: bytes
        :param servcie: the website/service of the account
        :type service: str
        :param user: the user's id
        :type user: int
        :param nonce: the number used once of the encrypted password so it can be used to decrypt it
        :type nonce: bytes
        :param tag: the authentication block of the password, verifies if it has been altered or not
        :type tag: bytes
        '''
        self.exe.execute('''UPDATE passwords SET encrypted_password = ?, nonce = ?, tag = ?
                         WHERE user_id = ? AND username = ? AND site = ?''', (pswd, nonce, tag, user, username, service))
        self.db.commit()


    def delete_password(self, username:str, service:str, user:int) -> bool:
        '''
        deltes a password of some service of a certain user

        :param username: the username of the service's/website's account
        :type username: str
        :param service: the service/website
        :type service: str
        :param user: the user's id
        :type user: int
        :return: True if there's a record with such parameters and the deletion was successful, otherwise False
        :rtype: bool
        '''
        self.exe.execute('''DELETE FROM passwords 
                        WHERE (user_id = ? AND username = ? AND site = ?);'''
                        ,(user, username, service))
        if self.exe.rowcount == 0:
            return False ## No such record found
        else:
            self.db.commit()
            return True
        

    def delete_all_passwords(self, user_id:int):
        '''
        deletes all the entries of a certain user

        :param user_id: the user's id
        :type user_id: int
        '''
        self.exe.execute("DELETE FROM passwords WHERE user_id = ?", (user_id,))
        self.db.commit()
