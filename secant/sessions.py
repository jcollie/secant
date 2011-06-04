#!/usr/bin/python
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

import os
import ipaddr

from secant import config
from secant import templates

import paisley

sessions = {}

class Session:
    def __init__(self):
        pass

class find_client(defer.Deferred):
    def __init__(self, address):
        defer.Deferred.__init__(self)
        self.address = ipaddr.IPAddress(address)
        self.server = paisley.CouchDB('127.0.0.1')

        network = ipaddr.IPNetwork(address).masked()
        keys = []
        while True:
            keys.append(str(network))
            if network.prefixlen == 0:
                break
            network = network.supernet().masked()

        self.query = self.server.openView('clients', 'clients_by_address', 'clients_by_address', keys = keys)
        self.query.addCallback(self.parseResult)
        self.query.addErrback(self.testErr)

    def parseResult(self, result):
        if len(result['rows']) == 0:
            log.msg('Creating a fake client for address %s' % self.address)
            client = Client(self.address)
            self.callback(client)

        else:
            if len(result['rows']) == 1:
                log.msg('Found %i client entry for address %s' % (len(result['rows']), self.address))
            else:
                log.msg('Found %i client entries for address %s' % (len(result['rows']), self.address))

            client = Client(address = self.address,
                            secret = result['rows'][0]['value'].get('secret', None),
                            description = result['rows'][0]['value'].get('description', None),
                            messages = result['rows'][0]['value'].get('messages', {}),
                            prompts = result['rows'][0]['value'].get('prompts', {}))
            self.callback(client)

    def testErr(self, failure):
        print 'testErr', failure
