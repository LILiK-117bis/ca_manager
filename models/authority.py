#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from peewee import *

import os
import os.path

from paths import *

__doc__= """
Module of base classes to handle authorities
"""

class Authority(Model):
    request_allowed = []

    # data stored in the database
    ca_id = CharField()
    name = CharField()
    serial = IntegerField()

    def __bool__(self):
        return os.path.exists(self.path)

    @property
    def path(self):
        return os.path.join(MANAGER_PATH, self.ca_id)

    def generate(self):
        raise NotImplementedError()

    def sign(self, request):
        raise NotImplementedError()

    def __repr__(self):
        return ( "%s %s" % ( self.__class__.__name__, self.ca_id ) )
