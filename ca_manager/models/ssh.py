#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os.path
import subprocess

from .authority import Authority
from .certificate import Certificate
from .request import SignRequest
from ..paths import *


class UserSSHRequest(SignRequest):
    def __init__(self, req_id, user_name, root_requested, key_data):
        super(UserSSHRequest, self).__init__(req_id)

        self.user_name = user_name
        self.root_requested = root_requested
        self.key_data = key_data

    @property
    def name(self):
        return 'User: %s [R:%d]' % (self.user_name, int(self.root_requested))

    @property
    def fields(self):
        return [
            ('User name', self.user_name),
            ('Root access requested', 'yes' if self.root_requested else 'no')
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
        return 'Hostname: %s' % self.host_name

    @property
    def fields(self):
        return [
            ('Hostname', self.host_name)
        ]

    @property
    def receiver(self):
        return self.host_name


class SSHAuthority(Authority):

    request_allowed = [UserSSHRequest, HostSSHRequest, ]

    key_algorithm = 'ed25519'

    user_validity = '+52w'
    host_validity = '+52w'

    def __bool__(self):
        """
        Check if key pair already exists
        """
        keys_pair_exist = os.path.exists(self.path) and os.path.exists(self.path + '.pub')

        return keys_pair_exist

    def generate(self):
        """
        Generate a SSHAuthority if the files associated
        do not exists
        """
        # check if the public key exists
        if not self:
            self.isRoot = True
            # let ssh-keygen do its job
            subprocess.check_output(['ssh-keygen',
                                     '-f', self.path,
                                     '-t', self.key_algorithm,
                                     '-C', self.name])

        else:
            raise ValueError('A CA with the same id already exists')

    def generate_certificate(self, request):
        """
        Sign a *SSHRequest with this certification authority
        """

        pub_key_path = request.destination

        ca_private_key = self.path

        if type(request) == UserSSHRequest:
            login_names = [request.user_name, ]
            if request.root_requested:
                login_names.append('root')

            subprocess.check_output(['ssh-keygen',
                                     '-s', ca_private_key,
                                     '-I', 'user_%s' % request.receiver,
                                     '-n', ','.join(login_names),
                                     '-V', self.user_validity,
                                     '-z', str(self.serial),
                                     pub_key_path])
            validity_interval = self.user_validity

        elif type(request) == HostSSHRequest:
            subprocess.check_output(['ssh-keygen',
                                     '-s', ca_private_key,
                                     '-I', 'host_%s' % request.receiver.replace('.', '_'),
                                     '-h',
                                     '-n', request.host_name,
                                     '-V', self.host_validity,
                                     '-z', str(self.serial),
                                     pub_key_path])
            validity_interval = self.host_validity

        return validity_interval
