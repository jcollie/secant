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
        self.state = 0
        self.username = None
        self.password = None
        self.old_password = None
        self.new_password_1 = None
        self.new_password_2 = None
        self.action = -1
        self.priv_lvl = -1
        self.authen_type = -1
        self.service = -1
        self.port = None
        self.rem_addr = None
        self.data = None
    
    def process_request(self, request):
        if self.state == 0:
            self.log.debug('authentication start')
            request = packet.AuthenticationStart(copy_of = request)

            self.action = request.action
            self.priv_lvl = request.priv_lvl
            self.authen_type = request.authen_type
            self.service = request.service
            self.port = request.port
            self.rem_addr = request.rem_addr
            self.data = request.data

            if self.action != packet.TAC_PLUS_AUTHEN_LOGIN:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = 'Only LOGIN authentication action is supported.'
                reply.data = b''
                return defer.succeed(reply)

            if self.authen_type != packet.TAC_PLUS_AUTHEN_TYPE_ASCII:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = 'Only ASCII authentication type is supported.'
                reply.data = b''
                return defer.succeed(reply)

            if self.service not in [ packet.TAC_PLUS_AUTHEN_SVC_LOGIN, packet.TAC_PLUS_AUTHEN_SVC_ENABLE ]:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = 'Only LOGIN or ENABLE authentication service is supported.'
                reply.data = b''
                return defer.succeed(reply)
            
            if self.username is None and request.user == '':
                return self.request_username(request)

            else:
                self.username = request.user
                return self.request_password(request)
        
        else:
            self.log.debug('authentication continue')
            request = packet.AuthenticationContinue(copy_of = request)

            if request.authentication_flags & packet.TAC_PLUS_CONTINUE_FLAG_ABORT:
                self.log.debug('Remote requested abort!')
                self.reset()
                return defer.succeed(None)

            if self.state == 1:
                if request.user_msg == '':
                    return self.request_username(request)
                
                self.username = request.user_msg
                return self.request_password(request)

            elif self.state == 2:
                if request.user_msg == '':
                    # change password
                    return self.request_old_password(request)

                else:
                    self.password = request.user_msg
                    return self.process_authentication(request)

            elif self.state == 3:
                if request.user_msg == '':
                    reply = request.get_reply()
                    reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                    reply.authentication_flags = 0
                    reply.server_msg = 'Need old password!'
                    reply.data = b''
                    return defer.succeed(reply)

                self.old_password = request.user_msg
                return self.request_new_password_1(request)

            elif self.state == 4:
                if request.user_msg == '':
                    reply = request.get_reply()
                    reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                    reply.authentication_flags = 0
                    reply.server_msg = 'Need new password 1!'
                    reply.data = b''
                    return defer.succeed(reply)

                self.new_password_1 = request.user_msg
                return self.request_new_password_2(request)

            elif self.state == 5:
                if request.user_msg == '':
                    reply = request.get_reply()
                    reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                    reply.authentication_flags = 0
                    reply.server_msg = 'Need new password 2!'
                    reply.data = b''
                    return defer.succeed(reply)

                self.new_password_2 = request.user_msg
                return self.process_authentication(request)
            
            else:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.authentication_flags = 0
                reply.server_msg = 'State machine having problems!'
                reply.data = b''
                return defer.succeed(reply)

    def request_username(self, request):
        self.log.debug('Requesting username...')
        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETUSER
        reply.authentication_flags = 0
        
        # TODO: re-add ability to add a banner and customize prompt
        reply.server_msg = 'Username: '
        reply.data = b''

        self.state = 1
        
        return defer.succeed(reply)

    def request_password(self, request):
        self.log.debug('Requesting password...')
        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETPASS
        reply.authentication_flags = packet.TAC_PLUS_REPLY_FLAG_NOECHO
        
        if self.service == packet.TAC_PLUS_AUTHEN_SVC_LOGIN:
            # TODO: re-add ability to customize prompt
            password_prompt = 'Password: '

        elif self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
            # TODO: re-add ability to customize prompt
            password_prompt = 'Enable: '
            
        else:
            password_prompt = 'Password: '

        reply.server_msg = password_prompt
        reply.data = b''
        
        self.state = 2
        
        return defer.succeed(reply)

    def request_old_password(self, request):
        self.log.debug('Requesting old password...')
        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETPASS
        reply.authentication_flags = packet.TAC_PLUS_REPLY_FLAG_NOECHO
        
        # TODO: re-add ability to customize prompt
        password_prompt = 'Old Password: '

        if self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
            # TODO: re-add ability to customize prompt
            password_prompt = 'Old Enable Password: '

        reply.server_msg = password_prompt
        reply.data = b''
        
        self.state = 3
        
        return defer.succeed(reply)

    def request_new_password_1(self, request):
        self.log.debug('Requesting new password 1...')
        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETPASS
        reply.authentication_flags = packet.TAC_PLUS_REPLY_FLAG_NOECHO
        
        # TODO: re-add ability to customize prompt
        password_prompt = 'New Password: '

        if self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
            # TODO: re-add ability to customize prompt
            password_prompt = 'New Enable Password: '

        reply.server_msg = password_prompt
        reply.data = b''
        
        self.state = 4
        
        return defer.succeed(reply)

    def request_new_password_2(self, request):
        self.log.debug('Requesting new password 2...')
        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETPASS
        reply.authentication_flags = packet.TAC_PLUS_REPLY_FLAG_NOECHO
        
        # TODO: re-add ability to customize prompt
        password_prompt = 'Re-enter New Password: '

        if self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
            # TODO: re-add ability to customize prompt
            password_prompt = 'Re-enter New Enable Password: '

        reply.server_msg = password_prompt
        reply.data = b''
        
        self.state = 5
        
        return defer.succeed(reply)
    
    def process_authentication(self, request):
        if self.username is None:
            self.log.debug('for some reason, we don\'t have a username!')
            reply = request.get_reply()
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
            reply.authentication_flags = 0
            reply.server_msg = 'State machine having problems!'
            reply.data = b''
            return defer.succeed(reply)
        
        self.log.debug('looking up user "{u:}"', u = self.username)
        d = users.find_user(self.username)
        d.addCallback(self.findUserSucceeded, request)
        d.addErrback(self.findUserFailed, request)
        return d
            
    def findUserSucceeded(self, user, request):
        self.log.debug('user found')
        
        if self.service == packet.TAC_PLUS_AUTHEN_SVC_LOGIN:
            password_type = 'login'

        elif self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
            password_type = 'enable'

        else:
            reply = request.get_reply()
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
            reply.authentication_flags = 0
            reply.server_msg = 'Only LOGIN or ENABLE authentication services are supported!'
            reply.data = b''
            return defer.succeed(reply)

        if self.password is not None:
            self.log.debug('doing standard authorization check')
            d = user.check_password(password_type, self.password)
            d.addCallback(self.authenticationSucceeded, user, password_type, request)
            d.addErrback(self.authenticationFailed, user, password_type, request)
            return d

        if self.old_password is not None and self.new_password_1 is not None and self.new_password_2 is not None:
            
            if self.new_password_1 != self.new_password_2:
                self.log.debug('new passwords do not match')
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.authentication_flags = 0
                reply.server_msg = 'New passwords do not match!'
                reply.data = b''
                return defer.succeed(reply)

            self.log.debug('new passwords match, sending to user object to check old password and change to new password')
            
            d = user.change_password(password_type, self.old_password, self.new_password_1)
            d.addCallback(self.changePasswordSucceeded, user, password_type, request)
            d.addErrback(self.changePasswordFailed, user, password_type, request)
            return d

        self.log.debug('don\'t know what to do')
        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
        reply.authentication_flags = 0
        reply.server_msg = ''
        reply.data = b''
        return defer.succeed(reply)
        
    def findUserFailed(self, reason, request):
        reply = request.get_reply()

        self.log.debug('Authentication failed: {r:}!', r = reason)
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL
        reply.authentication_flags = 0
        reply.server_msg = 'Authentication failed!!!'
        reply.data = b''
        return reply

    def authenticationSucceeded(self, succeeded, user, password_type, request):
        reply = request.get_reply()

        if succeeded:
            self.log.debug('Authentication successful!')
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_PASS
            
        else:
            self.log.debug('Authentication failed!')
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL

        reply.authentication_flags = 0
        # TODO: add ability to customize message
        reply.server_msg = ''
        reply.data = b''
        return reply

    def authenticationFailed(self, failure, succeeded, password_type, request):
        self.log.debug('Authentication failed: {r:}!', r = failure)

        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL
        reply.authentication_flags = 0
        reply.server_msg = 'Authentication failed!!!'
        reply.data = b''
        return reply

    def changePasswordSucceeded(self, suceeded, user, password_type, request):
        if succeeded:
            self.log.debug('Change password successful!')
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_PASS
            
        else:
            self.log.debug('Change password failed!')
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL

        reply.authentication_flags = 0
        # TODO: add ability to customize message
        reply.server_msg = 'Password successfully changed!'
        reply.data = b''
        return reply

    def changePasswordFailed(self, failure, succeeded, password_type, request):
        self.log.debug('Change password failed: {r:}!', r = failure)

        reply = request.get_reply()
        reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL
        reply.authentication_flags = 0
        reply.server_msg = 'Change password failed!!!'
        reply.data = b''
        return reply
    
