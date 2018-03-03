#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from playhouse.gfk import *

import os
from inspect import getsourcefile
import subprocess

from .authority import Authority
from .certificate import Certificate
from .request import SignRequest
from ..paths import *

import json


class HostSSLRequest(SignRequest):
    def __init__(self, req_id, host_name, key_data):
        super(HostSSLRequest, self).__init__(req_id)

        self.host_name = host_name
        self.key_data = key_data

    @property
    def name(self):
        return 'Hostname: %s' % self.host_name

    @property
    def fields(self):
        return [
            ('Hostname', self.host_name)
        ]

    @property
    def receiver(self):
        return self.host_name


class UserSSLRequest(SignRequest):
    def __init__(self, req_id, user_name, key_data):
        super(HostSSLRequest, self).__init__(req_id)

        self.user_name = user_name
        self.key_data = key_data

    @property
    def name(self):
        return 'User: {}'.format(self.user_name)

    @property
    def fields(self):
        return [
            ('User name', self.user_name)
        ]

    @property
    def receiver(self):
        return self.user_name


class CASSLRequest(SignRequest):
    def __init__(self, req_id, ca_name, key_data):
        super(CASSLRequest, self).__init__(req_id)

        self.ca_name = ca_name
        self.key_data = key_data

    @property
    def name(self):
        return 'CA name: %s' % self.ca_name

    @property
    def fields(self):
        return [
            ('CA name', self.ca_name)
        ]

    @property
    def receiver(self):
        return self.ca_name


class SSLAuthority(Authority):
    request_allowed = [HostSSLRequest, CASSLRequest, ]

    ca_key_algorithm = 'des3'
    key_length = '4096'

    key_algorithm = 'sha256'
    root_ca_validity = '3650'
    ca_validity = '1825'
    cert_validity = '365'

    def generate(self):
        if os.path.exists(self.path):
            raise ValueError('A CA with the same id and type already exists')
        confirm = input('Is a root CA? [y/N]> ')
        if confirm == 'y':
            self.isRoot = True
        else:
            self.isRoot = False

        subprocess.check_output(['openssl',
                                 'genrsa',
                                 '-%s' % self.ca_key_algorithm,
                                 '-out', '%s' % (self.path),
                                 self.key_length])
        if self.isRoot:
            subprocess.check_output(['openssl',
                                     'req',
                                     '-extensions', 'v3_root_ca',
                                     '-config', os.path.join(os.path.dirname(os.path.abspath(getsourcefile(lambda:0))), '../openssl-config/openssl.cnf'),
                                     '-new',
                                     '-x509',
                                     '-days', self.root_ca_validity,
                                     '-key', self.path,
                                     # '-extensions', 'v3_ca'
                                     '-out', '%s.pub' % self.path,
                                     # '-config', "%s.conf"%self.path
                                     ])
        else:
            subprocess.check_output(['openssl',
                                     'req',
                                     '-new',
                                     #'-x509',
                                     # '-days', self.ca_validity,
                                     '-key', self.path,
                                     # '-extensions', 'v3_ca'
                                     '-out', '%s.csr' % self.path,
                                     # '-config', "%s.conf"%self.path
                                     ])
            result_dict = {}
            result_dict['keyType'] = 'ssl_ca'
            result_dict['caName'] = self.ca_id
            with open("%s.csr" % self.path, 'r') as f:
                result_dict['keyData'] = "".join(f.readlines())

            request = {'type': 'sign_request', 'request': result_dict}
            print('Please sign the following request:')
            print(json.dumps(request))

        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(0))

    def generate_certificate(self, request):
        """
        Sign a *SSLRequest with this certification authority
        """

        if not os.path.exists('%s.pub' % self.path) and not self.isRoot:
            raise ValueError("The CA certificate '%s.pub' doesn't exists yet" % self.path)

        pub_key_path = request.destination
        cert_path = request.cert_destination

        with open(pub_key_path, 'w') as stream:
            stream.write(request.key_data)

        subprocess.check_output(['openssl',
                                 'x509',
                                 '-req',
                                 '-days', self.ca_validity,
                                 '-in', pub_key_path,
                                 '-CA', '%s.pub' % self.path,
                                 '-CAkey', self.path,
                                 '-CAcreateserial',
                                 '-out', cert_path,
                                 '-%s' % self.key_algorithm])

        if not self.isRoot:
            with open(cert_path, 'a') as cert_file:
                with open('%s.pub' % self.path) as ca_cert_file:
                    cert_file.writelines(ca_cert_file.readlines())
        return self.ca_validity
