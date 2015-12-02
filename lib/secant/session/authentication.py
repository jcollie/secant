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

from twisted.logger import Logger
from twisted.internet import defer

from secant import session
from secant import packet
from secant import config
from secant import users

class AuthenticationSessionHandler(session.SessionHandler):
    log = Logger()

    def __init__(self, client, session_id):
        session.SessionHandler.__init__(self, client, session_id)
        self.reset()
        self.banner_shown = False

    def reset(self):
        self.start = True
        self.username = ''
        self.password = ''
        self.action = -1
        self.priv_lvl = -1
        self.authen_type = -1
        self.service = -1
        self.port = None
        self.rem_addr = None
        self.data = None
    
    def process_request(self, request):
        if self.start:
            self.log.debug('authentication start')
            request = packet.AuthenticationStart(copy_of=request)

            #log_message = config.log_formats.get('authentication-start')
            #if log_message is not None:
            #    self.log.debug(log_message.render(session = self, request = request))
            
            self.action = request.action
            self.priv_lvl = request.priv_lvl
            self.authen_type = request.authen_type
            self.service = request.service
            self.username = request.user
            self.port = request.port
            self.rem_addr = request.rem_addr
            self.data = request.data

            if self.action != packet.TAC_PLUS_AUTHEN_LOGIN:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = 'Only LOGIN authentication action is supported.'
                reply.data = ''
                return defer.succeed(reply)

            if self.authen_type != packet.TAC_PLUS_AUTHEN_TYPE_ASCII:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = 'Only ASCII authentication type is supported.'
                reply.data = ''
                return defer.succeed(reply)
                
            self.start = False
        
        else:
            self.log.debug('authentication continue')
            request = packet.AuthenticationContinue(copy_of=request)

            #log_message = config.log_formats.get('authentication-continue')
            #if log_message is not None:
            #    self.log.debug(log_message.render(session = self, request = request))

            if request.authentication_flags & packet.TAC_PLUS_CONTINUE_FLAG_ABORT:
                self.log.debug('Remote requested abort!')
                self.reset()
                return defer.succeed(None)

            if self.username == '':
                self.username = request.user_msg

            elif self.password == '':
                self.password = request.user_msg

            else:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.authentication_flags = 0
                reply.server_msg = 'Already have username and password!'
                reply.data = b''
                return defer.succeed(reply)

        if self.username == '':
            self.log.debug('Requesting username...')
            reply = request.get_reply()
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETUSER
            reply.authentication_flags = 0
            reply.server_msg = ''

            #banner = self.client.get_message('banner')
            #if not self.banner_shown and banner is not None:
            #    reply.server_msg += banner.render(client = self.client, session = self, request = request)
            #    reply.server_msg += '\r\n\r\n'
            #    self.banner_shown = True

            #username_prompt = self.client.get_prompt('username')
            #if username_prompt is None:
            reply.server_msg += 'Username: '
                
            #if username_prompt is not None:
            #    reply.server_msg += username_prompt.render(client = self.client, session = self, request = request)
            #else:
            #    reply.server_msg += u'Username: '

            reply.data = b''
            return defer.succeed(reply)

        elif self.password == '':
            self.log.debug('Requesting password...')
            reply = request.get_reply()
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETPASS
            reply.authentication_flags = packet.TAC_PLUS_REPLY_FLAG_NOECHO

            if self.service == packet.TAC_PLUS_AUTHEN_SVC_LOGIN:
                password_prompt = self.client.get_prompt('password')
                if password_prompt is None:
                    password_prompt = 'Password: '

            elif self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
                password_prompt = self.client.get_prompt('enable')
                if password_prompt is None:
                    password_prompt = 'Enable: '

            else:
                password_prompt = 'Password: '

            #elif isinstance(password_prompt, str):
            #    reply.server_msg = password_prompt.decode('utf-8')
            #else:
            #    reply.server_msg = password_prompt.render(client = self.client, session = self, request = request)
            reply.server_msg = password_prompt
            reply.data = b''
            return defer.succeed(reply)

        else:
            user = users.find_user(self.username)
            user.addCallback(self.findUserSucceeded, request)
            user.addErrback(self.findUserFailed, request)
            return user

    def findUserSucceeded(self, user, request):
        if self.service == packet.TAC_PLUS_AUTHEN_SVC_LOGIN:
            password_type = 'login'

        elif self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
            password_type = 'enable'

        else:
            self.log.debug('Unknown authentication service: %i' % self.service)
            password_type = None

        d = user.check_password(password_type, self.password)
        d.addCallback(self.authenticationSucceeded, user, password_type, request)
        d.addErrback(self.authenticationFailed, user, password_type, request)

        return d

    def findUserFailed(self, reason, request):
        reply = request.get_reply()

        self.log.debug('Authentication failed: %s!' % reason)
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL
        reply.authentication_flags = 0
        reply.data = ''
        return reply

    def authenticationSucceeded(self, succeeded, user, password_type, request):
        reply = request.get_reply()

        self.log.debug('Authentication successful!')
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_PASS

        # message = user.get_authentication_message(succeeded, password_type)

        # if isinstance(message, unicode):
        #     reply.server_msg = message
        # elif isinstance(message, str):
        #     reply.server_msg = message.decode('utf-8')
        # else:
        #     reply.server_msg = message.render(client = self.client, session = self, request = request, user = user)

        reply.authentication_flags = 0
        reply.server_msg = ''
        reply.data = b''
        return reply

    def authenticationFailed(self, failure, succeeded, password_type, request):
        reply = request.get_reply()

        self.log.debug('Authentication failed!')
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL

        # message = user.get_authentication_message(succeeded, password_type)

        # if isinstance(message, unicode):
        #     reply.server_msg = message
        # elif isinstance(message, str):
        #     reply.server_msg = message.decode('utf-8')
        # else:
        #     reply.server_msg = message.render(client = self.client, session = self, request = request, user = user)

        reply.authentication_flags = 0
        reply.server_msg = ''
        reply.data = b''
        return reply
