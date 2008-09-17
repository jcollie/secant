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

from secant import config
from lxml import etree
from twisted.python import log
import os

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
            if config.globals.has_key('enable_password'):
                return config.globals['enable_password'] == password

            return False

        else:
            return self.enable_password == password

def find_user(username):
    global users

    if users.has_key(username):
        return users[username]

    return None

def load_users():
    global users

    for users_path in config.paths['users']:
        try:
            user_tree = etree.parse(users_path)

            user_elements = user_tree.xpath('/users/user')

            for user_element in user_elements:
                username = str(user_element.xpath('username/text()')[0])

                try:
                    login_password = str(user_element.xpath('authentication/password[@type="login"]/text()')[0])
                except IndexError:
                    login_password = None

                try:
                    enable_password = str(user_element.xpath('authentication/password[@type="enable"]/text()')[0])
                except IndexError:
                    enable_password = None

                users[username] = User(username,
                                       login_password = login_password,
                                       enable_password = enable_password)

            log.msg('Loaded users from "%s"' % os.path.realpath(users_path))

            break

        except IOError:
            log.msg('Unable to load users from "%s"' % users_path)
