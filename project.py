from database import Database
import generator
import helpers
import pyfiglet
import users
import sqlite3
import pwinput
import os
import re
import requests
from vault import Vault
from tabulate import tabulate


def main():
    ## Greeting and start menu
    print(pyfiglet.figlet_format("VAULTIX", font='big_money-sw'))
    print("Thank you for using vaultix")

    while True:
        mode = greeting()
        if mode in ['1', 'register']:
            while True:
                username = input("\nSet a username: ").strip()
                while not username:
                    username = input("\nSet a username: ").strip()

                print("\nNote: The password is used to derive your encryption key for the database, you are not going to use it to access your account")
                print("Note: The program uses windows hello in logging in so you wont need to use this password again")

                pswd = pwinput.pwinput(prompt="\nSet a password: ", mask='*').strip()

                try:
                    users.register(username, pswd)
                    print("\nRegisteration successful! Please log in :>")
                    break
                except sqlite3.IntegrityError:
                    print("\nSorry, there's an existing user with the same username :<")
                    print("Please pick another username")
                    pass
                
            continue
        elif mode in ['2', 'log in', 'login']:
            username = input("\nEnter the username: ").strip()
            while not username:
                username = input("\nEnter the username: ").strip()

            key = users.login(username)
            if key is None:
                os.system("cls")
                print("\nFailed to Authenticate :<")
                break
            elif key == "None":
                os.system("cls")
                print("\nInvalid username, there's no such user :<")
                break
            
            db = Database()
            user = db.get_user(username)
            vault = Vault(user[0], key, db)

            helpers.update_activity(_timeout)
            srvc = service()
            
            while service_logic(vault, srvc, username):
                helpers.update_activity(_timeout)
                srvc = service()
            
            os.system("cls")
            db.close()
            break
        else:
            os.system("cls")
            break
    
    print(pyfiglet.figlet_format("CYA", font='big_money-sw'))


def greeting():
    '''
    main menu

    :return: the choice of menu (register, login, or exit)
    :rtype: str
    '''
    print("\nChoose from the following menu:")
    menu = ["[1] Register", "[2] Log in (login)", "[3] Exit"]
    for choice in menu:
        print(choice)

    mode = input("\nEnter: ").strip().lower()
    while (mode not in ['1', 'register', '2', 'log in', 'login', '3', 'exit']):
        print("\nInvalid input :<\n")
        mode = input("\nEnter: ").strip().lower()

    return mode


def service():
    '''
    Once the user is logged in, prints all the available features of the tool

    :return: the choosen feature
    :rtype: str
    '''
    print("\nChoose from the following menu:")
    menu = ["[1] Retrieve password", "[2] Add record", "[3] Generate record", "[4] Update record", "[5] Delete record",
            "[6] Retrieve all records", "[7] Export to a csv file",
            "[8] Import from a csv file", "[9] Check strength", "[10] Delete current user"]
    for choice in menu:
        print(choice)

    mode = input("\nEnter: ").strip().lower()
    while mode not in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
                       'retrieve password', 'add record', 'generate record', 'update record',
                       'delete record', 'retrieve all records',
                       'export', 'import', 'check strength', 'delete current user']:
        print("\nInvalid input :<\n")
        mode = input("\nEnter: ").strip().lower()

    return mode


def service_logic(vault:Vault, srvc:str, username:str) -> bool:
    '''
    maps the feature to it's corresponding function and handles the continuity of the program after performing the task

    :return: True if the user wants to get back to the features menu and perform another task, False if the user wants to exit the program
    :rtype: bool
    '''
        
    if srvc in ['1', "retrieve password"]:
        retrieve_pswd(vault)
    elif srvc in ['2', 'add record']:
        add_record(vault)
    elif srvc in ['3', 'generate record']:
        generate_record(vault)
    elif srvc in ['4', 'update record']:
        update_record(vault)
    elif srvc in ['5', 'delete record']:
        delete_record(vault)
    elif srvc in ['6', 'retrieve all records']:
        retrieve_all_records(vault)
    elif srvc in ['7', 'export']:
        export(vault)
    elif srvc in ['8', 'import']:
        import_file(vault)
    elif srvc in ['9', 'check strength']:
        check_strength()
    elif srvc in ['10', 'delete current user']:
        if delete_user(username):
            return False

    while True:
        confirm = input("\nDo you want to get back to the menu? (y/n) ").strip().lower()
        if confirm in ['y', 'yes']:
            return True
        elif confirm in ['n', 'no']:
            return False


def retrieve_pswd(vault:Vault):
    '''
    retrieves a password and saves it to the clipboard

    :param vault: the vault object that handles the decryption and retrieving the password
    :type vault: Vault
    '''
    site = input("What's the name of the website/service? ").strip()
    while not site:
        site = input("What's the name of the website/service? ").strip()
        
    username = input("Enter the account's username: ").strip()
    while not username:
        username = input("Enter the account's username: ").strip()

    try:
        password = vault.get(site, username)
    except ValueError:
        print("Sorry, there's no such record in the database :<")
        return

    if password is None:
        print("Failed to retrieve the password\nThe password has been altered :<")
        return
    
    helpers.copy_to_clipboard(password)
    print("The password has been successfully retrieved and copied to the clipboard :>")
    helpers.clear_clipboard(300)


def add_record(vault:Vault, site:str=None, username:str=None, password:str=None):
    '''
    Adds a new record to the database

    :param vault: the vault object that handles encryption and decryption of the passwords
    :type vault: Vault
    :param site: the site of the account default value None, obtains value only if called from generate_record
    :type site: str
    :param username: the username of the account default value None, obtains value only if called from generate_record
    :type username:str
    :param password: the password of the account default value None, obtains value only if called from generate_record
    :type password: str
    '''
    if site is None:
        site = input("What's the name of the website/service? ").strip()
        while not site:
            site = input("What's the name of the website/service? ").strip()
    if username is None:
        username = input("Enter the account's username: ").strip()
        while not username:
            username = input("Enter the account's username: ").strip()
    if password is None:
        password = pwinput.pwinput(prompt="Enter the password: ", mask='*').strip()

    vault.add(site, username, password)
    print("\nThe record has been successfully added to the database!! :>")


def generate_record(vault:Vault):
    '''
    generates a new record or updates an existing one

    :param vault: the vault object that handles encryption and decryption of the password
    :type vault: Vault
    '''
    print("\nWhat do you want to do?")
    for mode in ['[1] New record', '[2] Update record']:
        print(mode)

    ans = input("\nEnter: ").strip().lower()
    while ans not in ['1', '2', 'new record', 'update record']:
        ans = input("Enter: ").strip().lower()

    site = input("What's the name of the website/service? ").strip()
    while not site:
        site = input("What's the name of the website/service? ").strip()
        
    username = input("Enter the account's username: ").strip()
    while not username:
        username = input("Enter the account's username: ").strip()

    while True:
        try:
            length = int(input("Enter the desired length of your password: "))
        except ValueError:
            print("Invalid input, Try again :<")

        if length < 12:
            print("The length must be greater than 12 :<")
        else:
            break

    password = generator.generate(length)

    if ans in ['1', 'new record']:
        add_record(vault, site, username, password)
    else:
        update_record(vault, site, username, password)

    helpers.copy_to_clipboard(password)
    print("The password has been successfully generated and copied to the clipboard :>")
    helpers.clear_clipboard(300)

    print("\nPassword analysis:")
    check_strength(password)


def delete_record(vault:Vault):
    '''
    deletes a record from the database

    :param vault: the vault object that handles the deleteion of the record from the database
    :type vault: Vault
    '''
    site = input("What's the name of the website/service? ").strip()
    while not site:
        site = input("What's the name of the website/service? ").strip()

    username = input("Enter the account's username: ").strip()
    while not username:
        username = input("Enter the account's username: ").strip()

    if helpers.confirmation(msg="Do you want to delete this record"):
        if vault.delete(site, username):
            print("The record has been successfully deleted :>")
        else:
            print("No such record found :<")
    else:
        print("Delete aborted :>")


def retrieve_all_records(vault:Vault):
    '''
    prints a table containing all the records of the current user

    :param vault: the vault object that handles the decryption of all the passwords
    :type vault: Vault
    '''
    data = vault.get_all()
    headers = ["Service", "Username", "Password"]
    print()
    print(tabulate(data, headers=headers, tablefmt='psql'))


def update_record(vault:Vault, site:str=None, username:str=None, password:str=None):
    '''
    updates an existing record to the database

    :param vault: the vault object that handles encryption and decryption of the passwords
    :type vault: Vault
    :param site: the site of the account default value None, obtains value only if called from generate_record
    :type site: str
    :param username: the username of the account default value None, obtains value only if called from generate_record
    :type username:str
    :param password: the password of the account default value None, obtains value only if called from generate_record
    :type password: str
    '''
    if site is None:
        site = input("What's the name of the website/service? ").strip()
        while not site:
            site = input("What's the name of the website/service? ").strip()
    if username is None:
        username = input("Enter the account's username: ").strip()
        while not username:
            username = input("Enter the account's username: ").strip()
    if password is None:
        password = pwinput.pwinput(prompt="Enter the password: ", mask='*').strip()

    vault.update(username, site, password)
    print("\nThe record has been updated successfully :>")


def export(vault:Vault):
    '''
    exports all the records to a csv file

    :param vault: the vault object that handles the decryption and writing to the file
    :type vault: Vault
    '''
    inputfile = input("\nSet the file's name: ").strip()

    while True:
        while not inputfile:
            inputfile = input("\nSet the file's name: ").strip()

        if vault.export(inputfile):
            print(f"\nRecords have been successfully exported, check {inputfile} :>")
            break
        print("\nUnsupported file extension, Try again :<")


def import_file(vault:Vault):
    '''
    imports all the records from a csv file to the database

    :param vault: the vault object that handles the encryption and reading from the file
    :type vault: Vault
    '''
    while True:
        filename = input("\nSet the file's name: ").strip()
        while not filename:
            filename = input("\nEnter the file's name: ").strip()

        try:
            if vault.import_file(filename):
                print("File imported successfully :>")
                break
            print("\nUnsupported file extension, Try again :<")
        except FileNotFoundError:
            print("\nSorry, couldn't find a file with such name :<")
        except KeyError:
            print("\nSorry, invalid csv schema :<")


def check_strength(pswd:str=None):
    '''
    checks the strength of a given passowrd and prints its analysis

    :param pswd: the password that going to be checked, default value None, obtains value only when called from generate_record
    :type pswd: str
    '''
    if pswd is None:
        pswd = ''
        while not pswd:
            pswd = pwinput.pwinput(prompt="Enter the password: ", mask='*').strip()

    try:
        feedback = helpers.check_strength(pswd)
        for key in feedback:
            if feedback[key]:
                print(f"{key} : {feedback[key][0]}") if key == 'suggestions' else print(f"{key} : {feedback[key]}")
    except requests.exceptions.ConnectionError:
        print("No Internet Connection :<")


def delete_user(username:str):
    '''
    deletes the current user using his username

    :param username: the username of the current user
    :type username: str
    :return: True if the deletion has beein confirmed and approved, otherwise False
    :rType: bool
    '''
    if helpers.confirmation("Do you want to delete this user"):
        valid = users.delete(username)
        if not valid[0] and not valid[1]:
            print("Invalid user, there's no user with such username")
            return False
        elif not valid[1]:
            print("Failed to authenticate :<")
            return False
        else:
            print("User has been successfully deleted :>")
            return True
    else:
        print("Delete aborted :>")
        return False
    

def _timeout():
    os.system('cls')
    print("\nSession timed out :<")
    print(pyfiglet.figlet_format("CYA", font='big_money-sw'))
    os._exit(0)


if __name__ == "__main__":
    main()