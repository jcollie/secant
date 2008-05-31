#!/usr/bin/python
# -*- mode: python -*-

import config
from lxml import etree

users = {}

class User:
    def __init__(self, username, login_password = None, enable_password = None):
        self.username = username
        self.login_password = login_password
        self.enable_password = enable_password

    def check_login_password(self, password):
        return self.login_password == password

    def check_enable_password(self, password):
        if self.enable_password is None:
            return config.global_enable_password == password
        else:
            return self.enable_password == password

def load_users():
    user_tree = etree.parse(config.users_file)
    
    user_elements = user_tree.xpath('/users/user')

    for user_element in user_elements:
        print dir(user_element)
        usernames = user_element.xpath('username')
        for username in usernames:
            print username.text

load_users()
