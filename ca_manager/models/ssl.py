#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
from tempfile import NamedTemporaryFile

from .authority import Authority
from .certificate import Certificate
from .request import SignRequest
from ..paths import *

import json


class HostSSLRequest(SignRequest):
    v3_exts = {
        'subjectKeyIdentifier': 'hash',
        'authorityKeyIdentifier': 'keyid:always, issuer',
        'basicConstraints': 'critical, CA:FALSE',
        'keyUsage': 'critical, digitalSignature, keyEncipherment',
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
    v3_exts = {
        'subjectKeyIdentifier': 'hash',
        'authorityKeyIdentifier': 'keyid:always, issuer',
        'basicConstraints': 'critical, CA:FALSE',
        'keyUsage': 'critical, digitalSignature',
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
    v3_exts = {
        'subjectKeyIdentifier': 'hash',
        'authorityKeyIdentifier': 'keyid:always, issuer',
        'basicConstraints': 'critical, CA:true, pathlen:0',
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

    key_encryption = 'aes256'

    key_format = 'ED25519'
    key_format_extra = {}

    #key_format = 'RSA'
    #key_format_extra = {
    #    'rsa_keygen_bits': 4096,
    #    'rsa_keygen_primes': 2,
    #    'rsa_keygen_pubexp': 65537,
    #}

    #key_format = 'EC'
    #key_format_extra = {
    #    'ec_paramgen_curve': 'P-256',
    #    'ec_param_enc': 'named_curve',
    #}

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

        # Create Private Key
        cmd = [
            'openssl',
            'genpkey',
            '-{}'.format(self.key_encryption),
            '-out', "{}.key".format(self.path),
            '-algorithm', self.key_format,
        ]
        for k, v in self.key_format_extra.items():
            cmd += ['-pkeyopt', '{}:{}'.format(k, v)]
        subprocess.check_output(cmd)

        # Create Certificate Request
        cmd = [
            'openssl',
            'req',
            '-new',
            '-key', "{}.key".format(self.path),
            '-out', "{}.csr".format(self.path),
        ]
        subprocess.check_output(cmd)

        if self.isRoot:
        # If CA is Root, generate self signed certificate
            v3_exts = {
                'subjectKeyIdentifier': 'hash',
                'authorityKeyIdentifier': 'keyid:always, issuer',
                'basicConstraints': 'critical, CA:true, pathlen:1',
                'keyUsage': 'cRLSign, keyCertSign',
                'subjectAltName': 'email:copy',
                'issuerAltName': 'issuer:copy',
            }
            with NamedTemporaryFile(mode='w') as extfile:
                extfile.writelines(
                    ["{} = {}\n".format(k, v)
                         for k, v in v3_exts.items()])
                extfile.flush()
                subprocess.check_output([
                    'openssl',
                    'x509',
                    '-req',
                    '-days', self.root_ca_validity,
                    '-in', "{}.csr".format(self.path),
                    '-signkey', "{}.key".format(self.path),
                    '-out', "{}.crt".format(self.path),
                    '-extfile', extfile.name,
                ])

        else:
        # If CA is not Root, format a JSON signing request
            result_dict = {}
            result_dict['keyType'] = 'ssl_ca'
            result_dict['caName'] = self.ca_id
            with open("{}.csr".format(self.path), 'r') as f:
                result_dict['keyData'] = "".join(f.readlines())
            request = {'type': 'sign_request', 'request': result_dict}
            print('Please sign the following request:')
            print(json.dumps(request))

        # Init CA serial
        with open(self.path + '.serial', 'w') as stream:
            stream.write('01\n')

    def generate_certificate(self, request):
        """
        Sign a *SSLRequest with this certification authority
        """

        if not os.path.exists('%s.crt' % self.path) and not self.isRoot:
            raise ValueError(
                "The CA certificate '%s.crt' doesn't exists yet" % self.path)

        csr_path = request.destination
        cert_path = request.cert_destination

        with open(csr_path, 'w') as stream:
            stream.write(request.key_data)

        with NamedTemporaryFile(mode='w') as extfile:
            extfile.writelines(
                ["{} = {}\n".format(k, v)
                     for k, v in request.v3_exts.items()])
            extfile.flush()
            subprocess.check_output([
                'openssl',
                'x509',
                '-req',
                '-days', self.ca_validity,
                '-in', csr_path,
                '-CA', "{}.crt".format(self.path),
                '-CAkey', "{}.key".format(self.path),
                '-CAserial', "{}.serial".format(self.path),
                '-out', cert_path,
                '-extfile', extfile.name,
            ])

        # If it's not a RootCA append the full chain to the output cert
        if not self.isRoot:
            with open(cert_path, 'a') as cert_file:
                with open("{}.crt".format(self.path), 'r') as ca_cert_file:
                    cert_file.writelines(ca_cert_file.readlines())
        return self.ca_validity
