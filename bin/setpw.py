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

import sys
import json

from twisted.internet import reactor
from twisted.logger import globalLogBeginner
from twisted.logger import textFileLogObserver
from twisted.logger import Logger

from txetcd.client import EtcdClient

import scrypt
import binascii

output = textFileLogObserver(sys.stdout)
globalLogBeginner.beginLoggingTo([output])

class Main(object):
    def __init__(self, username, passwords):
        self.username = username
        self.passwords = json.dumps(passwords).encode('utf-8')
        self.client = EtcdClient(reactor)
        reactor.callWhenRunning(self.setPasswords)

    def setPasswords(self):
        d = self.client.set('/secant/users/{}/passwords'.format(self.username),
                            value = self.passwords)
        d.addCallback(self.finish)

    def finish(self, result):
        reactor.stop()

passwords = {'login': {'salt': None,
                       'hash': None},
             'enable': {'salt': None,
                       'hash': None}}
login_password_salt = open('/dev/urandom', 'rb').read(64)
passwords['login']['salt'] = binascii.hexlify(login_password_salt).decode('ascii')
passwords['login']['hash'] = binascii.hexlify(scrypt.hash('hello', login_password_salt)).decode('ascii')
m = Main('jcollie', passwords)
reactor.run()
