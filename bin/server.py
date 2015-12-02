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

from twisted.internet import reactor
from twisted.internet import endpoints
from twisted.logger import globalLogBeginner
from twisted.logger import textFileLogObserver
from twisted.logger import Logger

from secant import config
from secant import TacacsProtocolFactory

output = textFileLogObserver(sys.stdout)
globalLogBeginner.beginLoggingTo([output])

factory = TacacsProtocolFactory()
endpoint = endpoints.serverFromString(reactor, 'tcp:port=49')
endpoint.listen(factory)

reactor.run()
