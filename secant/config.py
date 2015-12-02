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
from twisted.logger import Logger()
import os

from secant import templates

log = Logger()

default_paths = {'users': ['./users.xml', '/etc/secant/users.xml'],
                 'clients': ['./clients.xml', '/etc/secant/clients.xml'],
                 'genshi_templates': ['.', '/etc/secant']}

paths = {}

globals = {'enable_password': None,
           'client_secret': None}

messages = {'banner': None}
prompts = {'username': u'Username: ',
           'password': u'Password: '}

log_formats = {}

def load_config(config_paths=[]):
    global paths
    global globals

    if not config_paths:
        config_paths.append('./config.xml')
        config_paths.append('/etc/secant/config.xml')

    for config_path in config_paths:
        try:
            config_tree = etree.parse(config_path)
            config_tree.xinclude()

            config_file_elements = config_tree.xpath('/config/config-files/*')

            for config_file_element in config_file_elements:
                config_file_type = config_file_element.tag
                path_text_elements = config_file_element.xpath('path/text()')
                paths[config_file_type] = map(lambda path: str(path).strip(), path_text_elements)

            template_search_path_elements = config_tree.xpath('/config/template-search-paths/*')
            
            for template_search_path_element in template_search_path_elements:
                template_creator_name = template_search_path_element.tag
                template_search_path = map(lambda path: str(path).strip(),
                                           template_search_path_element.xpath('path/text()'))
                template_creator = templates.template_creators.get(template_creator_name)
                if template_creator is not None:
                    template_creator.update_search_path(template_search_path)
                else:
                    log.msg('Unknown template creator "%s"' % template_creator_name)

            global_elements = config_tree.xpath('/config/globals/*')

            for global_element in global_elements:
                global_name = global_element.tag
                globals[global_name] = templates.template_from_element(global_element)

            message_elements = config_tree.xpath('/config/messages/*')

            for message_element in message_elements:
                message_name = message_element.tag
                messages[message_name] = templates.template_from_element(message_element)

            prompt_elements = config_tree.xpath('/config/prompts/*')

            for prompt_element in prompt_elements:
                prompt_name = prompt_element.tag
                prompts[prompt_name] = templates.template_from_element(prompt_element)

            log_format_elements = config_tree.xpath('/config/log-formats/*')

            for log_format_element in log_format_elements:
                log_format_name = log_format_element.tag
                log_formats[log_format_name] = templates.template_from_element(log_format_element)
                
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
