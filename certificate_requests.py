#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import os.path
import sqlite3
import subprocess
import json

from paths import *

__doc__= """
Module of classes to handle certificate requests
"""

class SignRequest(object):
    def __init__(self, req_id):
        self.req_id = req_id

    def __repr__(self):
        return ( "%s %s" % ( str(self.__class__.__name__), str(self.req_id) ) )

    @property
    def name(self):
        raise NotImplementedError()

    @property
    def fields(self):
        raise NotImplementedError()

    @property
    def path(self):
        return os.path.join(REQUESTS_PATH, self.id)

class RequestLoader(object):
    """
    Context manager that loads a request from a file
    and return a Request type
    """

    def __init__(self, request_id):
        self.request_id = request_id
        self.request_dir = REQUESTS_PATH

    @property
    def path(self):
        return os.path.join(self.request_dir, self.request_id)

    def __enter__(self):
        with open(self.path, 'r') as stream:
            # read the json from a TextIO
            # but let as_request handle 
            # the conversion to a Python
            # object
            request_data = json.load(
                stream,
                )
    
    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            print(exc_type, exc_value)
            print(traceback)

class UserSSHRequest(SignRequest, object):
    def __init__(self, req_id, user_name, root_requested, key_data):
        super(UserSSHRequest, self).__init__(req_id)

        self.user_name = user_name
        self.root_requested = root_requested
        self.key_data = key_data

    @property
    def name(self):
        return "User: %s [R:%d]" % (self.user_name, int(self.root_requested))

    @property
    def fields(self):
        return [
            ("User name", self.user_name),
            ("Root access requested", 'yes' if self.root_requested else 'no')
        ]

    def __str__(self):
        return ("%s %s" % (self.req_id, self.user_name))

class HostSSLRequest(SignRequest, object):
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
    def __str__(self):
        return ("%s %s" % (self.req_id, self.host_name))

class HostSSHRequest(SignRequest, object):
    def __init__(self, req_id, host_name, key_data):
        super(HostSSHRequest, self).__init__(req_id)

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
    def __str__(self):
        return ("%s %s" % (self.req_id, self.host_name))


class Authority(object):
    ca_type = None

    def __init__(self, ca_id, name, ca_dir):
        self.ca_id = ca_id
        self.name = name
        self.ca_dir = ca_dir

    @property
    def path(self):
        return os.path.join(self.ca_dir, self.ca_id)

    def generate(self):
        raise NotImplementedError()

    def sign(self, request):
        raise NotImplementedError()

    def __repr__(self):
        return ( "%s %s" % ( self.__class__.__name__, self.ca_type ) )

class SSHAuthority(Authority):
    ca_type = 'ssh'

    key_algorithm = 'ed25519'

    user_validity = '+52w'
    host_validity = '+52w'

    def generate(self):
        if os.path.exists(self.path):
            raise ValueError("A CA with the same id and type already exists")

        subprocess.check_output(['ssh-keygen',
            '-f', self.path,
            '-t', self.key_algorithm,
            '-C', self.name])

        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(0))


    def sign(self, request):

        assert type(request) in [UserSSHRequest, HostSSHRequest]

        pub_key_path = os.path.join(OUTPUT_PATH, request.req_id + '.pub')
        cert_path = os.path.join(OUTPUT_PATH, request.req_id + '-cert.pub')

        with open(self.path + '.serial', 'r') as stream:
            next_serial = int(stream.read())
        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(next_serial + 1))

        with open(pub_key_path, 'w') as stream:
            stream.write(request.key_data)

        ca_private_key = self.path

        if type(request) == UserSSHRequest:
            login_names = [request.user_name]
            if request.root_requested:
                login_names.append('root')

            subprocess.check_output(['ssh-keygen',
                '-s', ca_private_key,
                '-I', 'user_%s' % request.user_name,
                '-n', ','.join(login_names),
                '-V', self.user_validity,
                '-z', str(next_serial),
                pub_key_path])
        elif type(request) == HostSSHRequest:
            subprocess.check_output(['ssh-keygen',
                '-s', ca_private_key,
                '-I', 'host_%s' % request.host_name.replace('.', '_'),
                '-h',
                '-n', request.host_name,
                '-V', self.host_validity,
                '-z', str(next_serial),
                pub_key_path])

        return cert_path

class SSLAuthority(Authority):
    ca_type = 'ssl'

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


    def sign(self, request):
        OUTPUT_PATH

        assert type(request) in [HostSSLRequest]

        pub_key_path = os.path.join(OUTPUT_PATH, request.req_id + '.pub')
        cert_path = os.path.join(OUTPUT_PATH, request.req_id + '-cert.pub')

        with open(self.path + '.serial', 'r') as stream:
            next_serial = int(stream.read())
        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(next_serial + 1))

        with open(pub_key_path, 'w') as stream:
            stream.write(request.key_data)

        ca_private_key = self.path

        # openssl x509 -req -days 360 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt        # print()
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

        return cert_path
