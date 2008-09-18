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
from twisted.python import log
import os

default_paths = {'users': ['./users.xml', '/etc/secant/users.xml'],
                 'clients': ['./clients.xml', '/etc/secant/clients.xml']}

paths = {}

globals = {'enable_password': None,
           'client_secret': None}

def load_config(config_paths=[]):
    global paths
    global globals

    if not config_paths:
        config_paths.append('./config.xml')
        config_paths.append('/etc/config.xml')

    for config_path in config_paths:
        try:
            config_tree = etree.parse(config_path)

            path_elements = config_tree.xpath('/config/paths/*')

            for path_element in path_elements:
                paths.setdefault(path_element.tag, []).append(path_element.text.strip())

            global_elements = config_tree.xpath('/config/globals/*')

            for global_element in global_elements:
                globals[global_element.tag] = global_element.text.strip()

            log.msg('Loaded configuration from "%s"' % os.path.realpath(config_path))

            break

        except IOError, e:
            log.msg('Unable to load configuration from "%s"' % config_path)

    for key, value in paths.items():
        if not value and key in default_paths:
            paths[key] = default_paths[key]

    for key, value in default_paths.items():
        if key not in paths:
            paths[key] = value
