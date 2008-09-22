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
    def __init__(self, username, passwords = {}, messages = {}):
        self.username = username
        self.passwords = passwords
        self.messages = messages

    def check_password(self, password_type, supplied_password):
        log.msg('Checking password: "%s" "%s" "%s"' % (self.username, password_type, supplied_password))
        if password_type is None:
            return False
        my_password = self.passwords.get(password_type)
        if my_password is None and password_type == 'enable':
            my_password = config.globals['enable_password']
        if my_password is None:
            return False
        return my_password == supplied_password

    def get_authentication_message(self, authentication_successful, password_type):
        if authentication_successful:
            message_name_base = 'authentication-success'
        else:
            message_name_base = 'authentication-failure'

        message_names = [message_name_base]
        
        if password_type is not None:
            message_names.insert(0, message_name_base + '-' + password_type)

        for message_name in message_names:
            message = self.messages.get(message_name)
            if message is None:
                message = config.messages.get(message_name)
            if message is not None:
                return message

        return ''

class AlwaysFailUser(User):
    def __init__(self, username):
        User.__init__(self, None)

    def check_password(self, password_type, supplied_password):
        return False

def find_user(username):
    global users
    global always_fail_user

    if username in users:
        return users[username]

    user = AlwaysFailUser(username)
    users[username] = user
    return user

def load_users():
    global users

    for users_path in config.paths['users']:
        try:
            user_tree = etree.parse(users_path)

            user_elements = user_tree.xpath('/users/user')

            for user_element in user_elements:
                username = str(user_element.xpath('username/text()')[0])

                passwords = {}
                password_elements = user_element.xpath('authentication/password')
                for password_element in password_elements:
                    password_type = password_element.get('type')
                    passwords[password_type] = password_element.text

                messages = {}
                message_elements = user_element.xpath('messages/*')
                for message_element in message_elements:
                    message_name = message_element.tag
                    messages[message_name] = templates.template_from_element(message_element)

                users[username] = User(username, passwords, messages)

            log.msg('Loaded users from "%s"' % os.path.realpath(users_path))

            break

        except IOError:
            log.msg('Unable to load users from "%s"' % users_path)
