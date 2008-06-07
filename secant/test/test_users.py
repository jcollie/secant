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

from secant.users import *

class TestUser:
    def test_1(self):
        assert User('test', 'test123', '321test').check_login_password('test123')

    def test_2(self):
        assert not User('test', 'test123', '321test').check_login_password('321test')

    def test_3(self):
        assert User('test', 'test123', '321test').check_enable_password('321test')

    def test_4(self):
        assert not User('test', 'test123', '321test').check_enable_password('test123')