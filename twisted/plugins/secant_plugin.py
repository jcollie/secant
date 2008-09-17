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

from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet
from twisted.internet.protocol import Factory

from secant import config
from secant import users
from secant import clients
from secant import TacacsProtocol

class SecantOptions(usage.Options):
    optParameters = [['port', 'p', 49, 'The port number to listen to']]

class SecantServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "secant"
    description = "TACACS+ Server"
    options = SecantOptions

    def makeService(self, options):
        config.load_config()
        users.load_users()
        clients.load_clients()

        factory = Factory()
        factory.protocol = TacacsProtocol
        internet.TCPServer(49, factory)

secantServiceMaker = SecantServiceMaker()
