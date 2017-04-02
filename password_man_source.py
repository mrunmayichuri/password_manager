# -*- coding: utf-8 -*-
#!/usr/bin/env python
#Password Man

import sys, struct, string
import os
from os import urandom
from random import choice
from Crypto.Cipher import AES
import base64
from Crypto.Random import random
from argparse import OPTIONAL
import Crypto.Util.Counter
from Crypto.Util import Counter
from sqlalchemy import *
import hashlib
import pyotp
from unidecode import unidecode
import passwordmeter

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

dictionary = {'upppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','lowercase': 'abcdefghijklmnopqrstuvwxyz',
             'numbers': '0123456789','special_characters': '^!\$%&/()=?{[]}+~#-_.:,;<>|\\'}

class PasswordMan(object):

    def __init__(self):

        #Prefix
        self.p = '\xd9_\xa6\xcf\x1dlc\xa0'
        # create database
        db = create_engine('sqlite:///crypto.db')
		# turn off verbose messages
        db.echo = False
		# metadata of the database
        metadata = MetaData(db)

        # define table 'fileinfo' with columns id, filename, filetype, md5, meta
        self.fileinfo = Table('fileinfo', metadata,
	    		Column('id', Integer, primary_key=True),
				Column('username', String),
	    		Column('password', String),
                Column('mode', String))

		# create table, check if exist then create
        self.fileinfo.create(checkfirst=True)

    #Function to read the username-password pair from the database
    def read_pass(self):

        uname = raw_input("Enter the username for which information is required:\n")
        s = self.fileinfo.select()
        rs = s.execute()
        not_found = False
        if rs:
            for row in rs:
                if row['username'] == uname:
                    if row['mode'] == '1':
                        print "Password: " + self.ecb_decryption(row['password'])
                        print "Mode: ECB\n"
                    elif row['mode'] == '2':
                        print "Password: " + self.ctr_decryption(row['password'])
                        print "Mode: CTR\n"
                    elif row['mode'] == '3':
                        print "Password: " + self.cbc_decryption(row['password'])
                        print "Mode: CBC\n"
                    else:
                        not_found = True

        if not_found:
            print "Username does not exist!\n"

    # show db content
    def show_db(self):
        show = self.fileinfo.select()
        rshow = show.execute()
        print "\n"
        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        print "\n                   PASSWORD DATABASE"
        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        for row in rshow:
            for val in row:
                if str(val).isdigit():
                    pass
            print str(row[1])+':     '+str(row[2])

        print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        print "\n"

    #Function to obtain user input, check if the username-password pair exists, if not, then write the username-password pair to the database
    def write_pass(self):
        exist_ecb = 0
        exist_ctr = 0
        exist_cbc = 0
        exist_ecb_uname = 0
        exist_ctr_uname = 0
        exist_cbc_uname = 0
        flag = 0
        uname = raw_input("Enter the username: ")

        while not uname:
            print "Empty username! Kindly enter the username again: "	#Checking if the user entered an empty username
            uname = raw_input()
        else:
            pword = raw_input("1. Enter the password:\n2. Generate complex password:\n Your Input: ")
            if pword == 1:
                pword = self.password_check(pword)						#Checking the entropy of the password
            else:
                pword = self.random_password_generator()
                print "New generated password is %s" % pword

            select_mode = raw_input("Enter the mode:\n 1. ECB\n 2. CTR\n 3. CBC\nYour input: ")

            s_only_uname = self.fileinfo.select().where(self.fileinfo.c.username == uname and self.fileinfo.c.mode == select_mode)
            only_uname = s_only_uname.execute()

            if select_mode == 1:
                s_uname_pword = self.fileinfo.select().where(self.fileinfo.c.username == uname and self.fileinfo.c.password == self.ebc_encryption(pword))
                uname_pword = s_uname_pword.execute()
                if only_uname:
                    exist_ecb_uname = 1
                if uname_pword:
                    exist_ecb = 1
            elif select_mode == 2:
                s_uname_pword = self.fileinfo.select().where(self.fileinfo.c.username == uname and self.fileinfo.c.password == self.ctr_encryption(pword))
                uname_pword = s_uname_pword.execute()
                if only_uname.fetchone():
                    exist_ctr_uname = 1
                if uname_pword.fetchone():
                    exist_ctr = 1
            else:
                s_uname_pword = self.fileinfo.select().where(self.fileinfo.c.username == uname and self.fileinfo.c.password == self.cbc_encryption(pword))
                uname_pword = s_uname_pword.execute()
                if only_uname.fetchone():
                    exist_cbc_uname = 1
                if uname_pword.fetchone():
                    exist_cbc = 1

            while not select_mode:
                print "Invalid option. Please enter the correct mode: "
                select_mode = raw_input()
            else:
                if exist_ecb == 1 or exist_ctr == 1 or exist_cbc == 1:	#Flags to check if the username-password pair exists in the database
                    flag = 1
                    print "This Username and Password pair already exists!"
                    new_pass_input = raw_input("Do you want to enter a new password for this Username? 1. YES  2. NO\nYour input: ")
                    if new_pass_input == '1':
                        pword = raw_input("Enter the new password: ")
                        pword = self.password_check(pword)
                        if select_mode == '1':
                            cipher_text = self.ecb_encryption(pword)
                            self.update_db(uname , cipher_text)
                        elif select_mode == '2':
                            cipher_text = self.ctr_encryption(pword)
                            self.update_db(uname , cipher_text)
                        else:
                            cipher_text = self.cbc_encryption(pword)
                            self.update_db(uname , cipher_text)
                elif exist_ecb_uname == 1 or exist_ctr_uname == 1 or exist_cbc_uname == 1: #Flags to check if the username exists in the database
                    if flag == 1:
                        pass
                    else:
                        print "This Username already exists!\n"
                        new_pass_input = raw_input("Do you want to enter a new password for this Username? 1. YES  2. NO\nYour input: ")
                        if new_pass_input == '1':
                            pword = raw_input("Enter the new password: ")
                            pword = self.password_check(pword)
                            if select_mode == '1':
                                cipher_text = self.ecb_encryption(pword)
                                self.update_db(uname , cipher_text)
                            elif select_mode == '2':
                                cipher_text = self.ctr_encryption(pword)
                                self.update_db(uname , cipher_text)
                            else:
                                cipher_text = self.cbc_encryption(pword)
                                self.update_db(uname , cipher_text)
                        else:
                            pass

                else:
                    if select_mode == '1':
                        self.save_to_db(uname, self.ecb_encryption(pword), select_mode)
                    elif select_mode == '2':
                        self.save_to_db(uname, self.ctr_encryption(pword), select_mode)
                    else:
                        self.save_to_db(uname, self.cbc_encryption(pword), select_mode)

    def save_to_db(self, uname, pword, smode):
        i = self.fileinfo.insert().values(username=uname, password=pword, mode=smode)
        i.execute()

    def delete_from_db(self, uname):
        d = self.fileinfo.delete().where(username = uname)
        d.execute()

    def update_db(self, uname, cipher_text):
        u = self.fileinfo.update().values(username=uname, password=cipher_text)
        u.execute()

    #Password security - checking the length of the password
    def password_check(self, pword):
        strength, improvements = passwordmeter.test(pword)
        if strength < 0.75:
            password = raw_input("Your password is weak. Please enter a new password: ")
        else:
            password = pword
        return password
        #~~Without using passwordmeter lib~~#
	#length = len(pword)
        #if length < 8:
        #   password = raw_input("Password length should be greater than or equal to 8. Please enter a new password: ")
        #else:
        #    password = pword
        #return password

    def random_password_generator(self):
        length=raw_input("Enter the length of the password to be generated (Enter a length greater than 8 characters): ")
        length=int(length)
        random_password = []

        while len(random_password) < length:
            key = choice(dictionary.keys())
            gen_char = urandom(1)
            if gen_char in dictionary[key]:
               random_password.append(gen_char)
        generated_random_password = ''.join(random_password)
        return generated_random_password

    def generate_random_password(self, pword):
        strength, improvements = passwordmeter.test(pword)
        while strength < 0.75:
            self.random_password_generator()

    #AES-ECB block cipher mode encryption and decryption functions
    def ecb_encryption(self, pword):
        aes_1 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_ECB)
        mod = len(pword) % 16
        pad  = 16 - mod
        #Padding
        if pad == 16:
            cipher_text = aes_1.encrypt(pword)
            cipher_text = base64.b64encode(cipher_text)
            return cipher_text
        else:
            pword += '0' * pad
            cipher_text = aes_1.encrypt(pword)
            cipher_text = base64.b64encode(cipher_text)
            return cipher_text

    def ecb_decryption(self, cipher_text):
        c = cipher_text
        cipher_text = base64.b64decode(c)
        aes_2 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_ECB)
        plain_text = aes_2.decrypt(cipher_text)
        plain_text = plain_text.strip('0')
        return plain_text

    #AES-CTR block cipher mode encryption and decryption functions
    def ctr_encryption(self, pword):
        aes_1 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CTR, counter = Counter.new(64, prefix = self.p))
        cipher_text = base64.b64encode(aes_1.encrypt(pword))
        return cipher_text

    def ctr_decryption(self, cipher_text):
        aes_2 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CTR, counter = Counter.new(64, prefix = self.p))
        plain_text = aes_2.decrypt(base64.b64decode(cipher_text))
        return plain_text

    #AES-CBC block cipher mode encryption and decryption functions
    def cbc_encryption(self, pword):
        aes_1 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CBC, 'ThisIsTheIV@666!')
        mod = len(pword) % 16
        pad  = 16 - mod
        #Padding
        if pad == 16:
            cipher_text = aes_1.encrypt(pword)
            cipher_text = base64.b64encode(cipher_text)
            return cipher_text
        else:
            pword += '0' * pad
            cipher_text = aes_1.encrypt(pword)
            cipher_text = base64.b64encode(cipher_text)
            return cipher_text

    def cbc_decryption(self, cipher_text):
        c = cipher_text
        cipher_text = base64.b64decode(c)
        aes_2 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CBC, 'ThisIsTheIV@666!')
        plain_text = aes_2.decrypt(cipher_text)
        plain_text = plain_text.strip('0')
        return plain_text

    def update_db_integrity(self):
        target = open('db_hash.txt', 'w')
        target.truncate()
        hasher = hashlib.md5()
        with open('crypto.db', 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        target.write(hasher.hexdigest())
        target.close()

    def check_db_integrity(self):
        target = open('db_hash.txt', 'r')
        hasher = hashlib.md5()
        with open('crypto.db', 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        db_hash = hasher.hexdigest()
        if str(db_hash).strip() == target.readline().strip():
            return True
        else:
            return False
#Main
def main():
    #Initializing the variable to count the number of attempts of the master password
    m = PasswordMan()
    chars=[]
    for i in range(16):
        chars.append(random.choice(ALPHABET))
    salt = "".join(chars)

    #m.update_db_integrity()
    if not m.check_db_integrity():
        print "DB is modified"
        sys.exit(0)

    attempt = 0
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    print "\n                      PASSWORD MAN"
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    while(True):
        begin = raw_input("Welcome to Password Man! Do you wish to continue? 1: Yes , 2: No\nYour input: ")
        if begin == '1':
            totp = pyotp.TOTP('masterofpuppetss')
            challenge = totp.now()
            #master_key = raw_input("Enter the master password and response separated by comma(,).\nThe randomly generated challenge is %s.\n" % challenge)
            master_key = raw_input("Enter the master password and response separated by comma(,):\n")
            master_val = master_key.split(',')
            #print master_val
            #Master password is hard-coded
            if hashlib.sha256(master_val[0]).hexdigest() == 'acee681a457d6cfb0e4300085e9b2c0f0ef8b72df5b2747cc5ca4c075a11cc91' and totp.verify(master_val[1]):
                #print master_key_hash
                command = raw_input("\nInput your choice:\n 1. Read password\n 2. Write & Save password\n 3. Show DB\n 4. Exit\nYour input: ")
                if command == '1':
                    m.read_pass()
                elif command == '2':
                    m.write_pass()
                elif command == '3':
                    m.show_db()
                else:
                    m.update_db_integrity()
                    sys.exit(0)

            else:
                print "Wrong master password. Try again. The app will close after 3 wrong attempts!"
                attempt = attempt + 1
                if attempt == 3:
                    sys.exit(0)
        elif begin == '2':
            m.update_db_integrity()
            sys.exit(0)
        else:
            print "Invalid input!"


if __name__=="__main__":
    main()
