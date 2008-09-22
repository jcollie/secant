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

import genshi.template
from twisted.python import log

# DO NOT IMPORT secant.config BECAUSE IT WILL CAUSE CIRCULAR IMPORTS!

class SecantTemplateError:
    pass

class GenshiTemplate(object):
    def __init__(self, template):
        self.template = template

    def render(self, *a, **kw):
        return self.template.generate(*a, **kw).render()

class GenshiTemplateCreator(object):
    def __init__(self, cls):
        self.cls = cls
        self.loader = genshi.template.TemplateLoader(search_path = [],
                                                     default_encoding = 'utf-8',
                                                     default_class = cls,
                                                     auto_reload = False)

    def update_search_path(self, search_path):
        self.loader.search_path = search_path

    def create_template(self, source = None, filename = None):
        if source is not None:
            return GenshiTemplate(self.cls(source,
                                           encoding = 'utf-8',
                                           loader = self.loader))
        if filename is not None:
            return GenshiTemplate(self.loader.load(filename,
                                                   cls = self.cls,
                                                   encoding = 'utf-8'))
        
        raise SecantTemplateError()

class PlainTemplate(object):
    def __init__(self, source):
        self.source = source

    def render(self, *a, **kw):
        return self.source

class PlainTemplateCreator(object):
    def __init__(self):
        self.search_path = []

    def update_search_path(self, search_path):
        self.search_path = search_path

    def create_template(self, source = None, filename = None):
        if source is None and filename is not None:
            if os.path.isabs(filename):
                try:
                    source = file(filename, 'rb').read()
                except IOError:
                    pass
            else:
                for search_path in self.search_path:
                    try:
                        source = file(os.path.join(search_path, filename), 'rb').read()
                    except IOError:
                        pass
        if source is None:
            raise SecantTemplateError()

        return PlainTemplate(source)

template_creators = {'genshi-newtext': GenshiTemplateCreator(cls = genshi.template.NewTextTemplate),
                     'genshi-oldtext': GenshiTemplateCreator(cls = genshi.template.OldTextTemplate),
                     'genshi-markup':  GenshiTemplateCreator(cls = genshi.template.MarkupTemplate),
                     'plain':          PlainTemplateCreator()}

def template_from_element(element):
    global template_creators
    template_creator_name = element.get('template', 'plain')
    template_creator = template_creators.get(template_creator_name)
    if template_creator is not None:
        log.msg('Using template creator "%s"' % (template_creator_name))
        filename = element.get('filename')
        if filename is None:
            template = template_creator.create_template(source = element.text)
        else:
            template = template_creator.create_template(filename = filename)
        return template
    else:
        log.msg('Invalid template creator "%s"' % (template_creator_name))
        raise SecantTemplateError()
