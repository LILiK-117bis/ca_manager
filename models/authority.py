#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from playhouse.gfk import *

from datetime import datetime

import os
import os.path

from models import customModel
from models.certificate import Certificate

from paths import *

__doc__= """
Module of base classes to handle authorities
"""

class Authority(customModel.CustomModel):

    signed_certificates = ReverseGFK(Certificate, 'authority_type', 'authority_id')

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
        assert type(request) in self.request_allowed

        # write the key data from the request into
        # the output folder
        with open(request.destination, 'w') as stream:
            stream.write(request.key_data)

        cert = Certificate(
                authority = self,
                cert_id = request.req_id,
                date_issued = datetime.now(),
                receiver = request.receiver,
                serial_number = self.serial,
                path = request.cert_destination,
                )

        cert.validity_interval = self.generate_certificate(request)

        cert.save()
        self.serial += 1
        return cert.path

    def generate_certificate(self, request):
        raise NotImplementedError()

    def __repr__(self):
        return ( "%s %s (%s), created on %s" % ( self.__class__.__name__, self.ca_id, self.name, self.creation_date) )
