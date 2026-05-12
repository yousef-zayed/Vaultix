import hashlib
from helpers import windows_hello_auth
import keyring
import secrets
from database import Database


def register(username:str, password:str):
    '''
    used to register a new user.

    :param username: the desired username set by the user
    :type username: str
    :param password: the main password for the account
    :param password: str
    :raise sqlite3.IntegrityError: if invalid user and the user already exists
    '''
    db = Database()
    salt = secrets.token_bytes(16) ## initializing the password salt for the user

    ## PBKDF2 configuration, key length 32, iteration 600k using sha256
    KLEN, ITERATIONS = 32, 600000
    hash_func = "sha256"

    try:
        db.add_user(username, salt)
        
        ## deriving the encryption key using PBKDF2 and storing it in windows credentials
        key = hashlib.pbkdf2_hmac(hash_func, password.encode(), salt, ITERATIONS, KLEN)
        keyring.set_password("vaultix", username, key.hex())
    finally:
        db.close()


def login(username:str) -> str | None:
    '''
    retrive the encryption key from windows credintial

    :param username: the username the account user name the user want to access
    :type username: str
    :return: the encryption key as a string in case of success otherwise None
    :rtype: str in case of success, None in case of failing to find the user or failing to authenticate
    '''
    db = Database()
    user = db.get_user(username)
    db.close()

    if not user:
         return "None"

    ## triggers the windows hello script for OS Authentication
    if windows_hello_auth(): 
        ## retrieving the password from windows credential
        return bytes.fromhex(keyring.get_password("vaultix", username))
    else:
         return None
    

def delete(username:str) -> tuple:
    '''
    deletes a user from the database, alongside all his passwords entries

    :param username: the username of the user that's going to get deleted
    :param username: str
    :return: a tuple (True, True) in case of success, (False, False) in case of invalid username, (True, False) in case of failed authentication
    '''
    db = Database()
    user = db.get_user(username)

    if not user:
        db.close()
        return (False, False) ## Invalid user "Doesn't exist"
    
    if windows_hello_auth():
        db.delete_all_passwords(user[0])
        db.delete_user(username)
        keyring.delete_password("vaultix", username)

        db.close()
        return (True, True) ## Valid user and successful authentication
    else:
        db.close()
        return (True, False) ## Valid user but failed to authenticate
