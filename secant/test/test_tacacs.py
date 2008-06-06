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

from secant.tacacs import *

class TestArgument:
    def test_1(self):
        assert str(Argument('a=b')) == 'a=b'

    def test_2(self):
        assert len(Argument('a=b')) == 3

    def test_3(self):
        assert Argument('a*b').key == 'a'

    def test_4(self):
        assert Argument('a*b').key == 'a'

    def test_5(self):
        assert Argument('a*b').is_optional

class TestPacket:
    def test_1(self):
        p = Packet()
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

class TestAuthenticationStart:
    def test_1(self):
        p = AuthenticationStart()
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

class TestAuthenticationReply:
    def test_1(self):
        p = AuthenticationReply(AuthenticationStart())
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'

class TestAuthenticationContinue:
    def test_1(self):
        p = AuthenticationContinue()
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

class TestAuthorizationRequest:
    def test_1(self):
        p = AuthorizationRequest()
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

class TestAuthorizationResponse:
    def test_1(self):
        p = AuthorizationResponse(AuthorizationRequest())
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'

class TestAccountingRequest:
    def test_1(self):
        p = AccountingRequest()
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

class TestAccountingReply:
    def test_1(self):
        p = AccountingReply(AccountingRequest())
        p.pack_header()
        print `p.header`
        assert p.header == '\xc0\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
