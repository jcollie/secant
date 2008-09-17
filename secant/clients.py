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

from secant import config
from lxml import etree
from twisted.python import log
import os

clients = {}

class Client:
    def __init__(self, secret, description):
        self.secret = secret
        self.description = description

def find_client(address):
    global clients

    if clients.has_key(address):
        return clients[address]

    return None

def load_clients():
    global clients

    for clients_path in config.paths['clients']:
        try:
            client_tree = etree.parse(clients_path)

            client_elements = client_tree.xpath('/clients/client')

            for client_element in client_elements:
                addresses = map(str, client_element.xpath('address/text()'))
                secret = str(client_element.xpath('secret/text()')[0])
                description = None
                try:
                    description = str(client_element.xpath('description/text()')[0])
                except IndexError:
                    pass
                client = Client(secret, description)
                for address in addresses:
                    clients[address] = client

            log.msg('Loaded clients from "%s"' % os.path.realpath(clients_path))

            break

        except IOError:
            log.msg('Cannot load clients from "%s"' % clients_path)
