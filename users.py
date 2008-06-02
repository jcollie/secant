#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

# Copyright © 2008 by Jeffrey C. Ollie
#
# This file is part of Secant.
#
# Secant is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Secant is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Secant.  If not, see <http://www.gnu.org/licenses/>.

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

class TestUser:
    def test_1(self):
        assert User('test', 'test123', '321test').check_login_password('test123')

    def test_2(self):
        assert not User('test', 'test123', '321test').check_login_password('321test')

    def test_3(self):
        assert User('test', 'test123', '321test').check_enable_password('321test')

    def test_4(self):
        assert not User('test', 'test123', '321test').check_enable_password('test123')

def load_users():
    user_tree = etree.parse(config.users_file)
    
    user_elements = user_tree.xpath('/users/user')

    for user_element in user_elements:
        print dir(user_element)
        usernames = user_element.xpath('username')
        for username in usernames:
            print username.text
