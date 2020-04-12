#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from playhouse.gfk import *

import os
import subprocess

from .authority import Authority
from .certificate import Certificate
from .request import SignRequest
from ..paths import *

import json


class HostSSLRequest(SignRequest):
    x509_extensions = {
        'keyUsage': 'digitalSignature,keyEncipherment',
        'extendedKeyUsage': 'serverAuth',
    }

    def __init__(self, req_id, host_name, key_data):
        super().__init__(req_id)

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
    x509_extensions = {
        'keyUsage': 'digitalSignature',
        'extendedKeyUsage': 'clientAuth',
    }

    def __init__(self, req_id, user_name, key_data):
        super().__init__(req_id)

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
    x509_extensions = {
        'subjectKeyIdentifier': 'hash',
        'authorityKeyIdentifier': 'keyid:always, issuer',
        'basicConstraints': 'critical, CA:true',
        'keyUsage': 'cRLSign, keyCertSign',
        'subjectAltName': 'email:copy',
        'issuerAltName': 'issuer:copy',
    }

    def __init__(self, req_id, ca_name, key_data):
        super().__init__(req_id)

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
    request_allowed = [
        HostSSLRequest,
        UserSSLRequest,
        CASSLRequest,
    ]

    ca_key_algorithm = 'des3'
    key_length = '4096'

    key_algorithm = 'sha256'
    root_ca_validity = '3650'
    ca_validity = '1825'
    cert_validity = '365'

    def generate(self):
        """
        Generate a Root or non Root Certification Authority
        """
        if os.path.exists(self.path):
            raise ValueError('A CA with the same id and type already exists')
        confirm = input('Is a root CA? [y/N]> ')
        if confirm == 'y':
            self.isRoot = True
        else:
            self.isRoot = False

        cmd = [
            'openssl',
            'genpkey',
            '-aes256',
            '-algorithm', 'ED25519',
            '-out', "{}.key".format(self.path),
        ]

        subprocess.check_output(cmd)

        cmd = [
            'openssl',
            'req',
            '-new',
            '-key', "{}.key".format(self.path),
        ]

        if self.isRoot:
            x509_ext = {
                'subjectKeyIdentifier': 'hash',
                'authorityKeyIdentifier': 'keyid:always, issuer',
                'basicConstraints': 'critical, CA:true, pathlen:1',
                'keyUsage': 'cRLSign, keyCertSign',
                'subjectAltName': 'email:copy',
                'issuerAltName': 'issuer:copy',
            }

            cmd += [
                '-x509',
                '-days', self.root_ca_validity,
                '-out', "{}.crt".format(self.path),
              ]

            for k, v in x509_ext.items():
                cmd += ['-addext', "{}={}".format(k, v)]

            subprocess.check_output(cmd)

        else:
            cmd += [
                '-out', "{}.csr".format(self.path),
            ]
            subprocess.check_output(cmd)

            result_dict = {}
            result_dict['keyType'] = 'ssl_ca'
            result_dict['caName'] = self.ca_id
            with open("{}.csr".format(self.path), 'r') as f:
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

        csr_path = request.destination
        cert_path = request.cert_destination

        with open(csr_path, 'w') as stream:
            stream.write(request.key_data)

        cmd = [
            'openssl',
            'x509',
            '-req',
            '-days', self.ca_validity,
            '-in', csr_path,
            '-CA', "{}.crt".format(self.path),
            '-CAkey', "{}.key".format(self.path),
            '-CAcreateserial',
            '-out', cert_path,
            '-extfile', '-',
        ]

        ext_string = '\n'.join(
            "{} = {}".format(k, v) for k, v in request.x509_extensions.items()
        )

        subprocess.check_output(cmd, input=ext_string.encode('utf-8'))

        # If it's not a RootCA append the full chain to the output cert
        if not self.isRoot:
            with open(cert_path, 'a') as cert_file:
                with open("{}.crt".format(self.path), 'r') as ca_cert_file:
                    cert_file.writelines(ca_cert_file.readlines())
        return self.ca_validity
