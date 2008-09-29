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

from twisted.internet.protocol import Protocol
from twisted.internet.address import IPv4Address
from twisted.python import log

from secant import tacacs
from secant import config
from secant import users
from secant import clients

__all__ = ['tacacs', 'clients', 'config', 'users', 'templates', 'test', 'TacacsProtocol']

class SessionHandler:
    def __init__(self, client, session_id):
        self.client = client
        self.session_id = session_id
        self.last_seq = 0

    def process_request(self, request):
        pass

class AuthenticationSessionHandler(SessionHandler):
    def __init__(self, client, session_id):
        SessionHandler.__init__(self, client, session_id)
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
            request = tacacs.AuthenticationStart(copy_of=request)

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

            if self.action != tacacs.TAC_PLUS_AUTHEN_LOGIN:
                reply = request.get_reply()
                reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = 'Only LOGIN authentication action is supported.'
                reply.data = ''
                return reply

            if self.authen_type != tacacs.TAC_PLUS_AUTHEN_TYPE_ASCII:
                reply = request.get_reply()
                reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.user_msg = 'Only ASCII authentication type is supported.'
                reply.data = ''
                return reply
                
            self.start = False
        
        else:
            request = tacacs.AuthenticationContinue(copy_of=request)

            log_message = config.log_formats.get('authentication-continue')
            if log_message is not None:
                log.msg(log_message.render(session = self, request = request))

            if request.authentication_flags & tacacs.TAC_PLUS_CONTINUE_FLAG_ABORT:
                log.msg('Remote requested abort!')
                self.reset()
                return None

            if self.username == '':
                self.username = request.user_msg

            elif self.password == '':
                self.password = request.user_msg

            else:
                reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_ERROR
                reply.authentication_flags = 0
                reply.server_msg = 'Already have username and password!'
                reply.data = ''
                
        reply = request.get_reply()

        if self.username == '':
            log.msg('Requesting username...')
            reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_GETUSER
            reply.authentication_flags = 0
            reply.server_msg = ''

            banner = self.client.get_message('banner')
            if not self.banner_shown and banner is not None:
                reply.server_msg += banner.render(client = self.client, session = self, request = request)
                reply.server_msg += '\r\n\r\n'
                self.banner_shown = True

            username_prompt = self.client.get_prompt('username')
            if username_prompt is not None:
                reply.server_msg += username_prompt.render(client = self.client, session = self, request = request)
            else:
                reply.server_msg += 'Username: '

            reply.data = ''
            return reply

        elif self.password == '':
            log.msg('Requesting password...')
            reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_GETPASS
            reply.authentication_flags = tacacs.TAC_PLUS_REPLY_FLAG_NOECHO

            if self.service == tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN:
                password_prompt = self.client.get_prompt('password')
                if password_prompt is None:
                    password_prompt = 'Password: '

            elif self.service == tacacs.TAC_PLUS_AUTHEN_SVC_ENABLE:
                password_prompt = self.client.get_prompt('enable')
                if password_prompt is None:
                    password_prompt = 'Enable: '

            else:
                password_prompt = 'Password: '

            if isinstance(password_prompt, basestring):
                reply.server_msg = password_prompt
            else:
                reply.server_msg = password_prompt.render(client = self.client, session = self, request = request)

            reply.data = ''
            return reply

        else:
            user = users.find_user(self.username)

            message_type_base = 'authentication-failed'

            if self.service == tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN:
                password_type = 'login'

            elif self.service == tacacs.TAC_PLUS_AUTHEN_SVC_ENABLE:
                password_type = 'enable'

            else:
                log.msg('Unknown authentication service: %i' % self.service)
                password_type = None

            authentication_successful = user.check_password(password_type, self.password)

            if authentication_successful:
                log.msg('Authentication successful!')
                reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_PASS

            else:
                log.msg('Authentication failed!')
                reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_FAIL

            message = user.get_authentication_message(authentication_successful, password_type)

            if isinstance(message, basestring):
                reply.server_msg = message
            else:
                reply.server_msg = message.render(client = self.client, session = self, request = request, user = user)

            reply.authentication_flags = 0
            reply.data = ''
            return reply

class AuthorizationSessionHandler(SessionHandler):
    def __init__(self, client, session_id):
        SessionHandler.__init__(self, client, session_id)
    
    def process_request(self, request):
        request = tacacs.AuthorizationRequest(copy_of=request)

        log_message = config.log_formats.get('authorization')
        if log_message is not None:
            log.msg(log_message.render(session = self, request = request))

        #if request.user == '':
        #    reply = request.get_reply()
        #    reply.authorization_status = tacacs.TAC_PLUS_AUTHOR_STATUS_ERROR
        #    reply.server_msg = 'No username supplied!'
        #    return reply

        reply = request.get_reply()
        reply.authorization_status = tacacs.TAC_PLUS_AUTHOR_STATUS_PASS_ADD

        service = None
        cmd = None
        cmd_arg = []
        
        for arg in request.args:
            if arg.key == 'service':
                service = arg.value
            if arg.key == 'cmd':
                cmd = arg.value
            if arg.key == 'cmd-arg':
                cmd_arg.append(arg.value)

        if service == 'shell' and cmd == '':
            reply.server_msg = 'Shell request granted!'
            #reply.args.append(tacacs.Argument('priv-lvl=15'))
        else:
            reply.server_msg = 'Other request granted!'
            
        return reply
    
class AccountingSessionHandler(SessionHandler):
    def __init__(self, client, session_id):
        SessionHandler.__init__(self, client, session_id)
    
    def process_request(self, request):
        request = tacacs.AccountingRequest(copy_of=request)

        log_message = config.log_formats.get('accounting')
        if log_message is not None:
            log.msg(log_message.render(session = self, request = request))
        
        reply = request.get_reply()
        reply.accounting_status = tacacs.TAC_PLUS_ACCT_STATUS_SUCCESS

        return reply

class TacacsProtocol(Protocol):
    def __init__(self):
        self.buffer = ''
        self.request = None
        self.handlers = {}
        self.client = None

    def connectionMade(self):
        log.msg('Connection made.')
        self.transport.setTcpNoDelay(True)

        self.peer = self.transport.getPeer()
        if isinstance(self.peer, IPv4Address):
            self.client = clients.find_client(self.peer.host)
        if self.client is None:
            log.msg('Don\'t know remote address!')
            self.transport.loseConnection()

    def dataReceived(self, data):
        self.buffer += data
        log.msg('Received %i bytes.' % len(data))

        # If we aren't in the middle of processing a request see if we
        # have enough data for the TACACS+ header, which is always 12
        # bytes.  If we have enough data for the header, start a
        # generic request and decode the header so we know how many
        # bytes to expect for the body of the request.
        if self.request is None and len(self.buffer) >= 12:
            request_header = self.buffer[:12]
            self.buffer = self.buffer[12:]
            
            # Start a generic request packet using the header.
            self.request = tacacs.Packet(self.client.get_secret().render())
            self.request.set_header(request_header)

            log.msg('Header received, need %i bytes for the body.' % self.request.length)

        # We've gotten enough data for the header and have started a
        # request, see if we have enough data for the body so we can
        # finish creating the generic request and can dispatch it to
        # the appropriate handler.
        if self.request is not None and len(self.buffer) >= self.request.length:
            log.msg('%i bytes received for the body.' % self.request.length)

            request_body = self.buffer[:self.request.length]
            self.buffer = self.buffer[self.request.length:]

            self.request.set_body(request_body)

            # Is this a request from a session we have already seen?
            if self.handlers.has_key(self.request.session_id):
                # Yes, look up the handler from our cache.
                handler = self.handlers[self.request.session_id]

            else:
                # No, create a new session handler based upon the request type.
                if self.request.packet_type == tacacs.TAC_PLUS_AUTHEN:
                    log.msg('New authentication session.')
                    handler = AuthenticationSessionHandler(self.client, self.request.session_id)

                elif self.request.packet_type == tacacs.TAC_PLUS_AUTHOR:
                    log.msg('New authorization session.')
                    handler = AuthorizationSessionHandler(self.client, self.request.session_id)

                elif self.request.packet_type == tacacs.TAC_PLUS_ACCT:
                    log.msg('New accounting session.')
                    handler = AccountingSessionHandler(self.client, self.request.session_id)

                # Cache the new handler for the next request
                self.handlers[self.request.session_id] = handler

            # Dispatch the request to the handler
            # TODO: handle this in a deferred?
            reply = handler.process_request(self.request)

            # If the handler returns a reply, send the reply back to the client.
            if reply != None:
                if self.request.header_flags & tacacs.TAC_PLUS_SINGLE_CONNECT_FLAG:
                    reply.header_flags |= tacacs.TAC_PLUS_SINGLE_CONNECT_FLAG
                log.msg('Sending reply.')
                self.transport.write(reply.pack())

            # Reset so that we start looking for a new request
            self.request = None

    def connectionLost(self, reason):
        log.msg('Connection lost: %s' % reason)
