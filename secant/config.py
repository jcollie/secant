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

from lxml import etree

paths = {'users': 'users.xml',
         'clients': 'clients.xml'}

globals = {'enable_password': None,
           'client_secret': None}

def load_config():
    global paths
    global globals

    config_tree = etree.parse('config.xml')
    
    path_elements = config_tree.xpath('/config/paths/*')

    for path_element in path_elements:
        paths[path_element.tag] = path_element.text.strip()

    global_elements = config_tree.xpath('/config/globals/*')

    for global_element in global_elements:
        globals[global_element.tag] = global_element.text.strip()
