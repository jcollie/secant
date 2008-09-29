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
from secant.session import authentication
from secant.session import authorization
from secant.session import accounting

__all__ = ['tacacs', 'clients', 'config', 'users', 'templates', 'session', 'test', 'TacacsProtocol']

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
                    handler = authentication.AuthenticationSessionHandler(self.client, self.request.session_id)

                elif self.request.packet_type == tacacs.TAC_PLUS_AUTHOR:
                    log.msg('New authorization session.')
                    handler = authorization.AuthorizationSessionHandler(self.client, self.request.session_id)

                elif self.request.packet_type == tacacs.TAC_PLUS_ACCT:
                    log.msg('New accounting session.')
                    handler = accounting.AccountingSessionHandler(self.client, self.request.session_id)

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
