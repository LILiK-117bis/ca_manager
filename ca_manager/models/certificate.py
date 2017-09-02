#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from playhouse.gfk import *

import os
import json

from .customModel import CustomModel

from ..paths import *


class Certificate(CustomModel):
    """
    """

    authority_type = CharField(null=True)
    authority_id = IntegerField(null=True)
    authority = GFKField('authority_type', 'authority_id')

    cert_id = CharField(
                index = True,
                unique = True,
                help_text = 'id shared with the sign request',
                )

    date_issued = DateTimeField(
                help_text = 'certificate\'s issue date',
                )

    receiver = CharField(
                help_text = 'hostname or list of user for this certificate',
                )

    serial_number = IntegerField(
                help_text = 'certificate\'s progressive number',
                )

    validity_interval = CharField(
                help_text = 'how long will the certificate be valid',
                )

    path = CharField(
                help_text = 'certificate\'s path on filesystem',
                )

    revoked = BooleanField(
                index = True,
                default = False,
                help_text = 'certificate lifecycle state',
                )

    def __repr__(self):
        msg = """<%s:%s> for %s
                signed %s by %s"""
        return (
                msg % (self.__class__.__name__, self.cert_id, self.receiver, self.date_issued, self.authority)
                )

    def __bool__(self):
        return os.path.exists(self.path)
