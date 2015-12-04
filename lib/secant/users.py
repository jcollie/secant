#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

# Copyright © 2008,2010 by Jeffrey C. Ollie
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

from twisted.internet import reactor
from twisted.logger import Logger
from twisted.internet import defer
from twisted.web import error

from txetcd.client import EtcdClient

import os
import time
import scrypt
import binascii
import json

class User:
    log = Logger()

    def __init__(self, username, passwords = {}, messages = {}, authorization_rules = [], passwords_index = None):
        self.username = username
        self.passwords = passwords
        self.passwords_index = passwords_index
        self.messages = messages
        self.authorization_rules = authorization_rules

    def check_password(self, password_type, supplied_password):
        self.log.debug('Checking password type {t:} for user {u:}', t = password_type, u = self.username)
        
        if password_type not in ['login', 'enable']:
            self.log.info('Authentication failed because password type {t:} is unsupported.', t = password_type)
            return defer.succeed(False)

        current_password_salt = binascii.unhexlify(self.passwords.get(password_type, {}).get('salt', ''))
        current_password_hash = binascii.unhexlify(self.passwords.get(password_type, {}).get('hash', ''))

        if (current_password_salt == '' or current_password_hash == '') and password_type == 'enable':
            self.log.debug('User "{u:}" does not have an enable password, falling back to login password', u = self.username)
            current_password_salt = binascii.unhexlify(self.passwords.get('login', {}).get('salt', ''))
            current_password_hash = binascii.unhexlify(self.passwords.get('login', {}).get('hash', ''))

        if current_password_salt == '' and current_password_hash == '':
            self.log.debug('Authentication failed for user "{u:}" because the user does not have a password set in the database',
                           u = self.username)
            return defer.succeed(False)

        supplied_password_hash = scrypt.hash(supplied_password, current_password_salt)
        
        if current_password_hash == supplied_password_hash:
            self.log.debug('Authentication for user {u:} succeeded.', u = self.username)
            return defer.succeed(True)

        else:
            self.log.debug('Authentication for user {u:} failed.', u = self.username)
            return defer.succeed(False)

    def change_password(self, password_type, old_supplied_password, new_supplied_password):
        finished = defer.Deferred()
        d = self.check_password(password_type, old_supplied_password)
        d.addCallback(self.change_password_1, password_type, new_supplied_password, finished)
        return finished
    
    def change_password_1(self, result, password_type, new_supplied_password, finished):
        if not result:
            self.log.debug('Not changing password because old password does not match!')
            finished.callback(False)

        new_supplied_password_salt = open('/dev/urandom', 'rb').read(64)
        new_supplied_password_hash = scrypt.hash(new_supplied_password, new_supplied_password_hash)
        self.passwords[password_type]['salt'] = binascii.hexlify(new_supplied_password_salt).decode('ascii')
        self.passwords[password_type]['hash'] = binascii.hexlify(new_supplied_password_hash).decode('ascii')
        value = json.dumps(self.passwords).encode('utf-8')
        
        d = self.client.set('/secant/users/{}/passwords'.format(self.username),
                            value = value,
                            prev_index = self.passwords_index)
        d.addCallback(self.change_password_2, finished)
    
    def change_password_2(self, result, finished):
        finished.callback(True)
        
class AlwaysFailUser(User):
    def __init__(self, username):
        User.__init__(self, username)

    def check_password(self, password_type, supplied_password):
        return defer.succeed(False)

class AlwaysSucceedUser(User):
    def __init__(self, username):
        User.__init__(self, username)

    def check_password(self, password_type, supplied_password):
        return defer.succeed(True)

#def find_user(username):
#    return defer.succeed(AlwaysSucceedUser(username))

class find_user(defer.Deferred):
    log = Logger()

    def __init__(self, username):
        defer.Deferred.__init__(self)
        self.log.debug('looking for user: {u:}', u = username)
        self.username = username
        self.client = EtcdClient(reactor)
        d = self.client.get('/secant/users/{}/passwords'.format(self.username))
        d.addCallbacks(self.gotResponse, self.errResponse)
        
    def gotResponse(self, response):
        passwords = json.loads(response.node.value)
        passwords_index = response.node.modifiedIndex
        self.callback(User(username = self.username,
                           passwords = passwords,
                           passwords_index = response.node.modifiedIndex))

    def errResponse(self, failure):
        self.errback(failure)
