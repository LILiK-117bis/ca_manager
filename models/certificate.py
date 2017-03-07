#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from peewee import *

import os
import json

from models import customModel

from models.authority import Authority
from paths import *


class Certificate(customModel.CustomModel):
    """
    """

    signed_by = ForeignKeyField(
            Authority,
            related_name = 'signed_certificates',
            )

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

    def __repr__(self):
        return ( "%s %s" % ( str(self.__class__.__name__), str(self.cert_id) ) )

    def __bool__(self):
        return os.path.exists(self.path)

    @property
    def path(self):
        return os.path.join(OUTPUT_PATH, self.cert_id + '-cert.pub')
