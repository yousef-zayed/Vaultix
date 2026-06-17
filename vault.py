from database import Database
from Crypto.Cipher import AES
import csv
import re


class Vault:
    def __init__(self, user_id:int, key:bytes, db:Database):
        self.user = user_id
        self.key = key
        self.db = db


    def delete(self, service:str, username:str) -> bool:
        '''
        deletes a record from the database

        :param service: the service of which the password associated
        :type service: str
        :param username: the username associated with the password
        :type username: str
        :return: True if there's a record with such parameters and the deletion was successful, otherwise False
        :rtype: bool
        '''
        return self.db.delete_password(username, service, self.user)

    
    def add(self, service:str, username:str, password:str):
        '''
        adds a new record to the database after encrypting the password

        :param service: the service or the website of the account
        :type service: str
        :param username: the account's username
        :type username: str
        :param password: the account's password
        '''
        ## creates the cipher, nonce, and tag and saves them in the database with the password
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(password.encode())
        self.db.add_password(username, ciphertext, service, self.user, cipher.nonce, tag)

    
    def get(self, service:str, username:str) -> str | None:
        '''
        retrives a specific password from the database

        :param service: the service or the website of the account
        :type service: str
        :param username: the account's username
        :type username: str
        :raise ValueError: if there's no matching entries
        :return: the decrypted password of the account or None in case the password has been altered
        :rtype: str
        '''
        ## gets the password and verifies it using the tag associated with it
        ## if the verification failed then the password has been altered and returns none
        ciphertext = self.db.get_password(service=service, username=username, user=self.user)
        if ciphertext != None:
            plaintext = self._decrypt(*ciphertext)
            if plaintext is None:
                return None ## the password has been altered
            else:
                return plaintext ## success
        raise ValueError
            

    def get_all(self) -> list:
        ''' 
        retrives all the passwords associated with the user

        :return: list of lists, each list is a the record's details (service, username, decrypted password)
        :rtype: list
        '''
        entries = self.db.get_all_passwords(self.user)
        plaintext_entries = []

        for entry in entries:
            ## for each entry it summons _decrypt() method to verify and decrypt the password
            ## if the verification failed then it saves 'tampered' in the password field
            plaintext = self._decrypt(entry[2], entry[3], entry[4])
            if plaintext is None:
                plaintext_entries.append((entry[0], entry[1], "⚠ tampered"))
            else:
                plaintext_entries.append([entry[0], entry[1], plaintext])

        return plaintext_entries
    

    def update(self, username:str, service:str, pswd:str):
        '''
        updates an existing record in the database

        :param service: the service or the website of the account
        :type service: str
        :param username: the account's username
        :type username: str
        :param password: the account's password
        '''
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pswd.encode())
        self.db.update_password(username, ciphertext, service, self.user, cipher.nonce, tag)


    def _decrypt(self, ciphertext:bytes, nonce:bytes, tag:bytes) -> str | None:
        ## decrypts the ciphertext and verifies it
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            return plaintext.decode('utf-8')
        except ValueError:
            return None
        

    def export(self, filename:str) -> bool:
        '''
        creates a csv file with the given file name contaisns all the user's database enteries

        :param filename: the desired name of the csv file
        :type filename: str
        :return: True if was successful, False if failed
        :rtype: bool
        '''
        ## verifying a valid output file
        if re.search(r".*\.csv$", filename):
            pswds = self.get_all()
            with open(filename, 'w') as output:
                ## writing to the csv file as a dictionary
                fieldnames = ['service', 'username', 'password']
                writer = csv.DictWriter(output, fieldnames=fieldnames)

                writer.writeheader()
                for entry in pswds:
                    writer.writerow({"service" : entry[0],
                                     "username" : entry[1],
                                     "password" : entry[2]})
                    
                return True
        else:
            return False
        

    def import_file(self, filename:str) -> bool:
        '''
        imports accounts' details from a csv file

        :param filename: the name of the csv file contianing the entries
        :type filename: str
        :raise KeyError: if invalid csv schema
        :raise FileNotFoundError: if couldn't find the file
        :return: True if was successful, False if failed
        :rtype: bool
        '''
        ## verifying a valid input file
        if re.search(r".*\.csv$", filename):
            with open(filename, newline='') as output:
                ## reading from the csv file as a dictionary 
                ## if not the right csv schema returns an Error message
                reader = csv.DictReader(output)
                for row in reader:
                    self.add(row["service"], row["username"], row["password"])

            return True
        else:
            return False
