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

from twisted.python import log
from twisted.internet import defer

from secant import config
from secant import session
from secant import packet
from secant import users

import paisley

class AuthorizationSessionHandler(session.SessionHandler):
    def __init__(self, client, session_id):
        session.SessionHandler.__init__(self, client, session_id)
    
        self.server = paisley.CouchDB('127.0.0.1')

        self.user = None
        self.service = None
        self.command = None
        self.command_arguments = None

    def process_request(self, request):
        request = packet.AuthorizationRequest(copy_of = request)

        log_message = config.log_formats.get('authorization')
        if log_message is not None:
            log.msg(log_message.render(session = self, request = request))

        if request.user == '':
            reply = request.get_reply()
            reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_ERROR
            reply.server_msg = 'No username supplied!'
            return defer.succeed(reply)

        d = users.find_user(request.user)
        d.addCallback(self.findUserSucceeded, request)
        return d

    def findUserSucceeded(self, user, request):
        self.user = user
        
        for argument in request.args:
            if argument.key == u'service':
                self.service = argument.value
            if argument.key == u'cmd':
                self.command = argument.value
            if argument.key == u'cmd-arg':
                self.command_arguments.append(argument.value)

        #print service, command, command_arguments
        #print user.authorization_rules

        reply = request.get_reply()
        reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_PASS_ADD

        for authorization_rule in user.authorization_rules:
            if authorization_rule['service'] == self.service and authorization_rule['command'] == self.command:
                if authorization_rule.has_key('status'):
                    if authorization_rule['status'] == 'fail':
                        reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_FAIL
                    elif authorization_rule['status'] == 'pass_repl':
                        reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
                    elif authorization_rule['status'] == 'pass_add':
                        reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
                    else:
                        reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
                else:
                    reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
                if authorization_rule.has_key('arguments'):
                    for key in authorization_rule['arguments']:
                        if isinstance(authorization_rule['arguments'][key], dict):
                            value = authorization_rule['arguments'][key].get('value')
                            is_optional = authorization_rule['arguments'][key].get('is_optional', False)
                        else:
                            value = authorization_rule['arguments'][key]
                            is_optional = False

                        reply.args.append(packet.Argument(key = key, value = value, is_optional = is_optional))
                break
        
        reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        return reply
