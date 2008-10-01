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

from twisted.python import log

from secant import session
from secant import packet
from secant import config
from secant import users

class AuthenticationSessionHandler(session.SessionHandler):
    def __init__(self, client, session_id):
        session.SessionHandler.__init__(self, client, session_id)
        self.reset()
        self.banner_shown = False

    def reset(self):
        self.start = True
        self.username = u''
        self.password = u''
        self.action = -1
        self.priv_lvl = -1
        self.authen_type = -1
        self.service = -1
        self.port = None
        self.rem_addr = None
        self.data = None
    
    def process_request(self, request):
        if self.start:
            request = packet.AuthenticationStart(copy_of=request)

            log_message = config.log_formats.get('authentication-start')
            if log_message is not None:
                log.msg(log_message.render(session = self, request = request))
            
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
                reply.user_msg = u'Only LOGIN authentication action is supported.'
                reply.data = ''
                return reply

            if self.authen_type != packet.TAC_PLUS_AUTHEN_TYPE_ASCII:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = u'Only ASCII authentication type is supported.'
                reply.data = ''
                return reply
                
            self.start = False
        
        else:
            request = packet.AuthenticationContinue(copy_of=request)

            log_message = config.log_formats.get('authentication-continue')
            if log_message is not None:
                log.msg(log_message.render(session = self, request = request))

            if request.authentication_flags & packet.TAC_PLUS_CONTINUE_FLAG_ABORT:
                log.msg('Remote requested abort!')
                self.reset()
                return None

            if self.username == u'':
                self.username = request.user_msg

            elif self.password == u'':
                self.password = request.user_msg

            else:
                reply = request.get_reply()
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.authentication_flags = 0
                reply.server_msg = u'Already have username and password!'
                reply.data = ''
                return reply

        reply = request.get_reply()

        if self.username == u'':
            log.msg('Requesting username...')
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETUSER
            reply.authentication_flags = 0
            reply.server_msg = u''

            banner = self.client.get_message('banner')
            if not self.banner_shown and banner is not None:
                reply.server_msg += banner.render(client = self.client, session = self, request = request)
                reply.server_msg += u'\r\n\r\n'
                self.banner_shown = True

            username_prompt = self.client.get_prompt('username')
            if username_prompt is not None:
                reply.server_msg += username_prompt.render(client = self.client, session = self, request = request)
            else:
                reply.server_msg += u'Username: '

            reply.data = ''
            return reply

        elif self.password == u'':
            log.msg('Requesting password...')
            reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_GETPASS
            reply.authentication_flags = packet.TAC_PLUS_REPLY_FLAG_NOECHO

            if self.service == packet.TAC_PLUS_AUTHEN_SVC_LOGIN:
                password_prompt = self.client.get_prompt('password')
                if password_prompt is None:
                    password_prompt = u'Password: '

            elif self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
                password_prompt = self.client.get_prompt('enable')
                if password_prompt is None:
                    password_prompt = u'Enable: '

            else:
                password_prompt = u'Password: '

            if isinstance(password_prompt, unicode):
                reply.server_msg = password_prompt
            elif isinstance(password_prompt, str):
                reply.server_msg = password_prompt.decode('utf-8')
            else:
                reply.server_msg = password_prompt.render(client = self.client, session = self, request = request)

            reply.data = ''
            return reply

        else:
            user = users.find_user(self.username)

            if self.service == packet.TAC_PLUS_AUTHEN_SVC_LOGIN:
                password_type = 'login'

            elif self.service == packet.TAC_PLUS_AUTHEN_SVC_ENABLE:
                password_type = 'enable'

            else:
                log.msg('Unknown authentication service: %i' % self.service)
                password_type = None

            authentication_successful = user.check_password(password_type, self.password)

            if authentication_successful:
                log.msg('Authentication successful!')
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_PASS

            else:
                log.msg('Authentication failed!')
                reply.authentication_status = packet.TAC_PLUS_AUTHEN_STATUS_FAIL

            message = user.get_authentication_message(authentication_successful, password_type)

            if isinstance(message, unicode):
                reply.server_msg = message
            elif isinstance(message, str):
                reply.server_msg = message.decode('utf-8')
            else:
                reply.server_msg = message.render(client = self.client, session = self, request = request, user = user)

            reply.authentication_flags = 0
            reply.data = ''
            return reply
