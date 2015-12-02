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

from secant import session
from secant import packet

import time
import paisley

class AccountingSessionHandler(session.SessionHandler):
    def __init__(self, client, session_id):
        session.SessionHandler.__init__(self, client, session_id)
        self.server = paisley.CouchDB('127.0.0.1')

    def process_request(self, request):
        request = packet.AccountingRequest(copy_of = request)

        doc = {'record_type':      'http://fedorahosted.org/secant/accounting_record',
               'time':             time.time(),
               'session_id':       self.session_id,
               'accounting_flags': {},
               'authen_method':    packet.authen_meth_map.get(request.authen_method, request.authen_method),
               'priv_lvl':         packet.priv_lvl_map.get(request.priv_lvl, request.priv_lvl),
               'authen_service':   packet.authen_svc_map.get(request.authen_service, request.authen_service),
               'user':             request.user,
               'port':             request.port,
               'rem_addr':         request.rem_addr,
               'arguments':        {}}

        for flag in map(lambda power: pow(2, power), range(0,8)):
            if request.accounting_flags & flag:
                doc['accounting_flags'][request.accounting_flags & flag] = packet.acct_flag_map.get(request.accounting_flags & flag, '')

        for argument in request.args:
            doc['arguments'][argument.key] = {'value': argument.value,
                                              'is_optional': argument.is_optional}

        reply = request.get_reply()
        reply.accounting_status = packet.TAC_PLUS_ACCT_STATUS_SUCCESS

        return self.server.saveDoc('secant', doc).addCallback(lambda x: reply)
