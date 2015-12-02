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
from twisted.internet.error import ConnectionDone
from twisted.logger import Logger

from secant import packet
from secant import config
from secant import users
from secant import clients
from secant.session import authentication
from secant.session import authorization
from secant.session import accounting

__all__ = ['packet', 'clients', 'config', 'users', 'templates', 'session', 'test', 'TacacsProtocol']

class TacacsProtocol(Protocol):
    log = Logger()

    def __init__(self):
        self.buffer = ''
        self.request = None
        self.handlers = {}
        self.client = None

    def connectionMade(self):
        self.log.msg('Connection made.')
        self.transport.setTcpNoDelay(True)

        self.peer = self.transport.getPeer()
        if isinstance(self.peer, IPv4Address):
            d = clients.find_client(self.peer.host)
            d.addCallback(self.setClient)
            d.addErrback(self.errorClient)
            #return d

    def setClient(self, client):
        self.log.msg('setting client')
        self.client = client
        self.processData()

    def errorClient(self, failure):
        self.log.msg('Error getting client: %s' % failure)
        self.transport.loseConnection()

    def dataReceived(self, data):
        self.buffer += data
        self.log.msg('Received %i bytes.' % len(data))
        self.processData()

    def processData(self):
        if self.client is None:
            self.log.msg('Waiting for client info...\n')
            return

        # If we aren't in the middle of processing a request see if we
        # have enough data for the TACACS+ header, which is always 12
        # bytes.  If we have enough data for the header, start a
        # generic request and decode the header so we know how many
        # bytes to expect for the body of the request.
        if self.request is None and len(self.buffer) >= 12:
            request_header = self.buffer[:12]
            self.buffer = self.buffer[12:]
            
            # Start a generic request packet using the header.
            #self.request = packet.Packet(self.client.get_secret().render())
            self.request = packet.Packet(self.client.get_secret())
            self.request.set_header(request_header)

            self.log.msg('Header received, need %i bytes for the body.' % self.request.length)

        # We've gotten enough data for the header and have started a
        # request, see if we have enough data for the body so we can
        # finish creating the generic request and can dispatch it to
        # the appropriate handler.
        if self.request is not None and len(self.buffer) >= self.request.length:
            self.log.msg('%i bytes received for the body.' % self.request.length)

            request_body = self.buffer[:self.request.length]
            self.buffer = self.buffer[self.request.length:]

            self.request.set_body(request_body)

            self.processRequest()

    def processRequest(self):
        # Is this a request from a session we have already seen?
        if self.handlers.has_key(self.request.session_id):
            # Yes, look up the handler from our cache.
            handler = self.handlers[self.request.session_id]

        else:
            # No, create a new session handler based upon the request type.
            if self.request.packet_type == packet.TAC_PLUS_AUTHEN:
                self.log.msg('New authentication session %i.' % self.request.session_id)
                handler = authentication.AuthenticationSessionHandler(self.client, self.request.session_id)

            elif self.request.packet_type == packet.TAC_PLUS_AUTHOR:
                self.log.msg('New authorization session %i.' % self.request.session_id)
                handler = authorization.AuthorizationSessionHandler(self.client, self.request.session_id)

            elif self.request.packet_type == packet.TAC_PLUS_ACCT:
                self.log.msg('New accounting session %i.' % self.request.session_id)
                handler = accounting.AccountingSessionHandler(self.client, self.request.session_id)

            # Cache the new handler for the next request
            self.handlers[self.request.session_id] = handler

        # Dispatch the request to the handler
        reply_deferred = handler.process_request(self.request)
        reply_deferred.addCallback(self.handleReply)

    def handleReply(self, reply):
        # If the handler returns a reply, send the reply back to the client.
        if reply != None:
            if self.request.header_flags & packet.TAC_PLUS_SINGLE_CONNECT_FLAG:
                reply.header_flags |= packet.TAC_PLUS_SINGLE_CONNECT_FLAG
            self.log.msg('Sending reply.')
            self.transport.write(reply.pack())

        # Reset so that we start looking for a new request
        self.request = None

    def connectionLost(self, reason):
        if not isinstance(reason.value, ConnectionDone):
            self.log.msg('Connection lost: %s' % reason.value)
        else:
            self.log.msg('Connection closed cleanly.')
