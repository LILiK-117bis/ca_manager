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
    active = BooleanField()

    ca_id = CharField(
            index = True,
            unique = True,
            )

    creation_date = DateTimeField(
            help_text = 'authority creation date',
            )

    name = CharField(
            index = True,
            help_text = 'authority descriptive name',
            )

    serial = IntegerField(
            help_text = 'last certificate serial number',
            )

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
