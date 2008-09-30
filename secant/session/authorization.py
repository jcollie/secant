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

from secant import config
from secant import session
from secant import packet

class AuthorizationSessionHandler(session.SessionHandler):
    def __init__(self, client, session_id):
        session.SessionHandler.__init__(self, client, session_id)
    
    def process_request(self, request):
        request = packet.AuthorizationRequest(copy_of=request)

        log_message = config.log_formats.get('authorization')
        if log_message is not None:
            log.msg(log_message.render(session = self, request = request))

        #if request.user == '':
        #    reply = request.get_reply()
        #    reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_ERROR
        #    reply.server_msg = 'No username supplied!'
        #    return reply

        reply = request.get_reply()
        reply.authorization_status = packet.TAC_PLUS_AUTHOR_STATUS_PASS_ADD

        service = None
        cmd = None
        cmd_arg = []
        
        for arg in request.args:
            if arg.key == u'service':
                service = arg.value
            if arg.key == u'cmd':
                cmd = arg.value
            if arg.key == u'cmd-arg':
                cmd_arg.append(arg.value)

        if service == 'shell' and cmd == '':
            reply.server_msg = u'Shell request granted!'
            #reply.args.append(packet.Argument('priv-lvl=15'))
        else:
            reply.server_msg = u'Other request granted!'
            
        return reply
