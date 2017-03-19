#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from playhouse.gfk import *

import os
import os.path
import subprocess

from models.authority import Authority
from models.certificate import Certificate
from models.request import SignRequest
from paths import *

class HostSSLRequest(SignRequest):
    def __init__(self, req_id, host_name, key_data):
        super(HostSSLRequest, self).__init__(req_id)

        self.host_name = host_name
        self.key_data = key_data

    @property
    def name(self):
        return "Hostname: %s" % self.host_name

    @property
    def fields(self):
        return [
            ("Hostname", self.host_name)
        ]

    @property
    def receiver(self):
        return self.host_name

class SSLAuthority(Authority):
    request_allowed = [ HostSSLRequest, ]

    ca_key_algorithm = 'des3'
    key_length = '4096'

    key_algorithm = 'sha256'
    ca_validity = '365'
    cert_validity = '365'

    def generate(self):
        if os.path.exists(self.path):
            raise ValueError("A CA with the same id and type already exists")

        subprocess.check_output(['openssl',
            'genrsa',
            '-%s'%self.ca_key_algorithm,
            '-out', '%s'%(self.path),
            self.key_length])

        subprocess.check_output(['openssl',
            'req',
            '-new',
            '-x509',
            '-days', self.ca_validity,
            '-key', self.path,
            # '-extensions', 'v3_ca'
            '-out', "%s.pub"%self.path,
            # '-config', "%s.conf"%self.path
            ])

        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(0))


    def generate_certificate(self, request):
        """
        Sign a *SSLRequest with this certification authority
        """

        pub_key_path = request.destination
        cert_path = request.cert_destination

        with open(pub_key_path, 'w') as stream:
            stream.write(request.key_data)

        subprocess.check_output(['openssl',
                        'x509',
                        '-req',
                        '-days', self.ca_validity,
                        '-in', pub_key_path,
                        '-CA', "%s.pub"%self.path,
                        '-CAkey', self.path,
                        '-CAcreateserial',
                        '-out', cert_path,
                        '-%s'%self.key_algorithm])

        return self.ca_validity

