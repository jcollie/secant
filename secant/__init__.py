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

from twisted.internet.protocol import Protocol
from twisted.internet.address import IPv4Address
from twisted.python import log

from secant import tacacs
from secant import config
from secant import users
from secant import clients

__all__ = ['tacacs', 'clients', 'config', 'users', 'test', 'TacacsProtocol']

class SessionHandler:
    def __init__(self, session_id):
        self.session_id = session_id
        self.last_seq = 0

    def process_request(self, request):
        pass

class AuthenticationSessionHandler(SessionHandler):
    def __init__(self, session_id):
        SessionHandler.__init__(self, session_id)
        self.reset()
        
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

            log.msg('Authentication Start\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s' % (`request.action`,
                                                                                              `request.priv_lvl`,
                                                                                              `request.authen_type`,
                                                                                              `request.service`,
                                                                                              `request.user`,
                                                                                              `request.port`,
                                                                                              `request.rem_addr`,
                                                                                              `request.data`))
            
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

            log.msg('Authentication Continue\n\t%s\n\t%s\n\t%s' % (`request.authentication_flags`,
                                                                   `request.user_msg`,
                                                                   `request.data`))
            
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
            reply.server_msg = 'Username: '
            reply.data = ''
            return reply

        elif self.password == '':
            log.msg('Requesting password...')
            reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_GETPASS
            reply.authentication_flags = tacacs.TAC_PLUS_REPLY_FLAG_NOECHO
            reply.server_msg = 'Password: '
            reply.data = ''
            return reply

        else:
            user = users.find_user(self.username)

            if user is not None:
                if self.service == tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN:
                    if user.check_login_password(self.password):
                        log.msg('Authentication successful!')
                        reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_PASS
                        reply.authentication_flags = 0
                        reply.server_msg = 'Welcome!'
                        reply.data = ''
                        return reply

                if self.service == tacacs.TAC_PLUS_AUTHEN_SVC_ENABLE:
                    if user.check_enable_password(self.password):
                        log.msg('Authentication successful!')
                        reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_PASS
                        reply.authentication_flags = 0
                        reply.server_msg = 'Welcome!'
                        reply.data = ''
                        return reply

            log.msg('Authentication failed!')
            reply.authentication_status = tacacs.TAC_PLUS_AUTHEN_STATUS_FAIL
            reply.authentication_flags = 0
            reply.server_msg = 'Go Away!'
            reply.data = ''
            return reply

class AuthorizationSessionHandler(SessionHandler):
    def __init__(self, session_id):
        SessionHandler.__init__(self, session_id)
    
    def process_request(self, request):
        request = tacacs.AuthorizationRequest(copy_of=request)
        log.msg('Authorization\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s' % (`request.authen_method`,
                                                                                   `request.priv_lvl`,
                                                                                   `request.authen_type`,
                                                                                   `request.authen_service`,
                                                                                   `request.user`,
                                                                                   `request.port`,
                                                                                   `request.rem_addr`,
                                                                                   `request.args`))
                                                                                   
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
            reply.args.append(tacacs.Argument('priv-lvl=15'))
        else:
            reply.server_msg = 'Other request granted!'
            
        return reply
    
class AccountingSessionHandler(SessionHandler):
    def __init__(self, session_id):
        SessionHandler.__init__(self, session_id)
    
    def process_request(self, request):
        request = tacacs.AccountingRequest(copy_of=request)
        log.msg('Accounting\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s' % (`request.accounting_flags`,
                                                                                      `request.authen_method`,
                                                                                      `request.priv_lvl`,
                                                                                      `request.authen_type`,
                                                                                      `request.authen_service`,
                                                                                      `request.user`,
                                                                                      `request.port`,
                                                                                      `request.rem_addr`,
                                                                                      `request.args`))
        
        reply = request.get_reply()
        reply.accounting_status = tacacs.TAC_PLUS_ACCT_STATUS_SUCCESS

        return reply

class TacacsProtocol(Protocol):
    def __init__(self):
        self.buffer = ''
        self.request = None
        self.handlers = {}
        self.secret = None

    def connectionMade(self):
        log.msg('Connection made.')
        self.transport.setTcpNoDelay(True)
        #look up secret key here
        self.peer = self.transport.getPeer()
        if isinstance(self.peer, IPv4Address):
            client = clients.find_client(self.peer.host)
            if client is None:
                self.secret = config.globals['client_secret']
            else:
                self.secret = client.secret

    def dataReceived(self, data):
        self.buffer += data
        log.msg('Received %i bytes.' % len(data))

        if self.request is None and len(self.buffer) >= 12:
            request_header = self.buffer[:12]
            self.buffer = self.buffer[12:]
            
            self.request = tacacs.Packet(self.secret)
            self.request.set_header(request_header)

            log.msg('Header received, need %i bytes for the body.' % self.request.length)
            
        if self.request is not None and len(self.buffer) >= self.request.length:
            log.msg('%i bytes received for the body.' % self.request.length)
            request_body = self.buffer[:self.request.length]
            self.buffer = self.buffer[self.request.length:]

            self.request.set_body(request_body)

            if self.handlers.has_key(self.request.session_id):
                handler = self.handlers[self.request.session_id]

            else:
                if self.request.packet_type == tacacs.TAC_PLUS_AUTHEN:
                    log.msg('New authentication session.')
                    handler = AuthenticationSessionHandler(self.request.session_id)

                elif self.request.packet_type == tacacs.TAC_PLUS_AUTHOR:
                    log.msg('New authorization session.')
                    handler = AuthorizationSessionHandler(self.request.session_id)

                elif self.request.packet_type == tacacs.TAC_PLUS_ACCT:
                    log.msg('New accounting session.')
                    handler = AccountingSessionHandler(self.request.session_id)

                self.handlers[self.request.session_id] = handler

            reply = handler.process_request(self.request)
            if reply != None:
                if self.request.header_flags & tacacs.TAC_PLUS_SINGLE_CONNECT_FLAG:
                    reply.header_flags |= tacacs.TAC_PLUS_SINGLE_CONNECT_FLAG
                log.msg('Sending reply.')
                self.transport.write(reply.pack())

            self.request = None

    def connectionLost(self, reason):
        log.msg('Connection lost: %s' % reason)
