#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from playhouse.gfk import *

import os
import json

from models import customModel

from paths import *


class Certificate(customModel.CustomModel):
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

    def __repr__(self):
        return ( "%s %s for %s on %s" % (self.__class__.__name__, self.cert_id, self.receiver, self.date_issued))

    def __bool__(self):
        return os.path.exists(self.path)

    @property
    def path(self):
        return os.path.join(OUTPUT_PATH, self.cert_id + '-cert.pub')
