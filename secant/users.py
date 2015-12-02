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

from twisted.logger import Logger
from twisted.internet import defer
from twisted.web import error

import os
import time

import paisley

class User:
    log = Logger()

    def __init__(self, username, passwords = {}, messages = {}, authorization_rules = []):
        self.username = username
        self.passwords = passwords
        self.messages = messages
        self.authorization_rules = authorization_rules

        self.server = paisley.CouchDB('127.0.0.1')

    def log_authentication(self, succeeded, password_type, message):

        doc = {'record_type': 'http://fedorahosted.org/secant/authentication_record',
               'username': self.username,
               'succeeded': succeeded,
               'password_type': password_type,
               'message': message,
               'time': time.time()}

        self.log.msg(message)
        self.server.saveDoc('secant', doc)

    def check_password(self, password_type, supplied_password):
        self.log.msg('Checking password type %s for user %s' % (password_type, self.username))
        if password_type not in ['login', 'enable']:
            self.log_authentication(False, password_type, 'Authentication failed because password type %s is unsupported.' % (password_type,))
            return defer.fail(False)

        d = self.server.openView('secant', 'users', 'authentication_failures',
                                 startkey = [self.username, time.time() - (15 * 60)],
                                 endkey = [self.username, time.time() + (1 * 60)],
                                 reduce = True,
                                 group = True,
                                 group_level = 1)
        d.addCallback(self.authenticationFailuresResult, password_type, supplied_password)

        return d

    def authenticationFailuresResult(self, result, password_type, supplied_password):
    
        if len(result['rows']) == 1 and result['rows'][0]['key'][0] == self.username:
            if result['rows'][0]['value'] >= 3:
                self.log.msg('Too many failed authentication attempts in the last fifteen minutes!')
                return defer.fail(False)
            return self.check_password_final(password_type, supplied_password)

        elif len(result['rows']) >= 1:
            self.log.msg('Too many results!')
            return defer.fail(False)

        else:
            return self.check_password_final(password_type, supplied_password)

    def check_password_final(self, password_type, supplied_password):
        my_password = self.passwords.get(password_type)

        if my_password is None and password_type == 'enable':
            my_password = config.globals['enable_password'].render()
            self.log.msg('Getting global enable password for user %s' % (self.username,))

        if my_password is None:
            self.log_authentication(False, password_type, 'Authentication failed because password type %s for user %s can\'t be determined.' % (password_type, self.username))
            return defer.fail(False)

        if my_password == supplied_password:
            self.log_authentication(True, password_type, 'Authentication for user %s succeeded.' % (self.username,))
            return defer.succeed(True)

        else:
            self.log_authentication(False, password_type, 'Authentication for user %s failed.' % (self.username,))
            return defer.fail(False)

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

        return u''

#class AlwaysFailUser(User):
#    def __init__(self, username):
#        User.__init__(self, None)
#
#    def check_password(self, password_type, supplied_password):
#        return defer.fail(False)

class find_user(defer.Deferred):
    def __init__(self, username):
        defer.Deferred.__init__(self)
        self.username = username

        self.server = paisley.CouchDB('127.0.0.1')

        query = self.server.openView('secant', 'users', 'by_username', keys = [username])
        query.addCallback(self.parseResult)
        query.addErrback(self.errback)

    def parseResult(self, result):
        if len(result['rows']) == 0:
            self.errback('User %s not found!' % self.username)

        elif len(result['rows']) == 1:
            user = User(username = result['rows'][0]['value'].get('username', None),
                        passwords = result['rows'][0]['value'].get('passwords', {}),
                        messages = result['rows'][0]['value'].get('messages', {}),
                        authorization_rules = result['rows'][0]['value'].get('authorization_rules', []))
            self.callback(user)

        else:
            self.errback('Too many results!')
