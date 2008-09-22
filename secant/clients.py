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

from secant import config
from secant import templates

clients = {}

class Client:
    def __init__(self,
                 addresses,
                 secret = None,
                 description = None,
                 messages = {},
                 prompts = {}):

        self.addresses = addresses
        self.secret = secret
        self.description = description
        self.messages = messages
        self.prompts = prompts

    def get_secret(self):
        if self.secret is None:
            return config.globals['client_secret']
        else:
            return self.secret

    def get_message(self, message_type):
        message = self.messages.get(message_type)
        if message is None:
            return config.messages.get(message_type)
        return message

    def get_prompt(self, prompt_type):
        prompt = self.prompts.get(prompt_type)
        if prompt is None:
            return config.prompts.get(prompt_type)
        return prompt

def find_client(address):
    global clients

    if clients.has_key(address):
        log.msg('Found client for address %s' % address)
        return clients[address]

    # Create a 'fake' client with global secret
    log.msg('Creating a fake client for address %s' % address)
    client = Client([address])
    clients[address] = client

    return client

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

                messages = {}
                message_elements = client_element.xpath('messages')
                for message_element in message_elements:
                    message_type = message_element.tag
                    messages[message_type] = templates.template_from_element(message_element)

                prompts = {}
                prompt_elements = client_element.xpath('prompts')
                for prompt_element in prompt_elements:
                    prompt_type = prompt_element.tag
                    prompts[prompt_type] = templates.template_from_element(prompt_element)

                client = Client(addresses,
                                secret = secret,
                                description = description,
                                messages = messages,
                                prompts = prompts)

                for address in addresses:
                    clients[address] = client

            log.msg('Loaded clients from "%s"' % os.path.realpath(clients_path))

            break

        except IOError:
            log.msg('Cannot load clients from "%s"' % clients_path)
