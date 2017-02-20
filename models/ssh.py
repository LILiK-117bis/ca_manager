#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from peewee import *

from datetime import datetime
import os.path
import subprocess

from models.authority import Authority
from models.certificate import Certificate
from models.request import SignRequest
from paths import *


class UserSSHRequest(SignRequest):
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

    @property
    def receiver(self):
        return self.user_name


class HostSSHRequest(SignRequest):
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

    @property
    def receiver(self):
        return self.host_name


class SSHAuthority(Authority):

    request_allowed = [ UserSSHRequest, HostSSHRequest, ]

    key_algorithm = 'ed25519'

    cert_validity = '+52w'

    def __bool__(self):
        """
        Check if key pair already exists
        """
        keys_pair_exist = os.path.exists(self.path) and os.path.exists(self.path + '.pub')

        return keys_couple_exist

    def generate(self):
        """
        Generate a SSHAuthority if the files associated
        do not exists
        """
        # check if the public key exists
        if not self:
            # let ssh-keygen do its job
            subprocess.check_output(['ssh-keygen',
                '-f', self.path,
                '-t', self.key_algorithm,
                '-C', self.name])

            # write the serial file with a value of
            # 0 for first certificate
            with open(self.path + '.serial', 'w') as stream:
                stream.write(str(0))

            super(SSHAuthority, self).generate()

        else:
            raise ValueError('A CA with the same id already exists')


    def sign(self, request):
        """
        Sign a *SSHRequest with this certification authority
        """

        assert type(request) in self.request_allowed

        pub_key_path = request.destination
        
        cert = Certificate(
                signed_by = self,
                cert_id = request.req_id,
                date_issued = datetime.now(),
                receiver = self.receiver,
                serial_number = self.serial,
                validity_interval = self.user_validity,
                )

        # write the key data from the request into
        # the output folder
        with open(request.destination, 'w') as stream:
            stream.write(request.key_data)

        ca_private_key = self.path

        if type(request) == UserSSHRequest:
            login_names = [ request.user_name, ]
            if request.root_requested:
                login_names.append('root')

            subprocess.check_output(['ssh-keygen',
                '-s', ca_private_key,
                '-I', 'user_%s' % request.user_name,
                '-n', ','.join(login_names),
                '-V', self.user_validity,
                '-z', str(self.serial),
                pub_key_path])


        elif type(request) == HostSSHRequest:
            subprocess.check_output(['ssh-keygen',
                '-s', ca_private_key,
                '-I', 'host_%s' % request.host_name.replace('.', '_'),
                '-h',
                '-n', request.host_name,
                '-V', self.host_validity,
                '-z', str(self.serial),
                pub_key_path])

        self.serial += 1

        cert.save()

        return cert.path


