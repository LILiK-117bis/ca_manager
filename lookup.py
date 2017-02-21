#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import hashlib
from itertools import chain
import json
import os
import os.path
import pickle
import shutil
import sqlite3
import tempfile

from models.ssh import SSHAuthority, UserSSHRequest, HostSSHRequest
from models.ssl import SSLAuthority, HostSSLRequest

from models.certificate import Certificate
from models.request import SignRequest

from paths import *

class CALookup(object):
    """
    Proxy to interact with authorities
    """

    allowed_auth = [
            SSHAuthority,
            SSLAuthority,
            ]

    def __init__(self):

        self.path = MANAGER_PATH

    def __iter__(self):

        all_the_authorities = [ auth.select().iterator() for auth in self.allowed_auth]

        return chain.from_iterable(all_the_authorities)


    def __getitem__(self, ca_id):

        if SSHAuthority(ca_id):

            return SSHAuthority(ca_id)

        elif SSLAuthority(ca_id):

            return SSLAuthority(ca_id)

        else:
            raise IndexError('Unknown CA "%s"' % ca_id)


class RequestLookup(object):
    """
    Proxy to interact with the requests
    """
    def __init__(self):
        self.request_dir = REQUESTS_PATH
        self.output_dir = OUTPUT_PATH

    def __iter__(self):
        """
        Iterate over all certificate request in REQUEST_PATH
        """

        for request_id in os.listdir(self.request_dir):
            """
            request_id is formatted as uuid
            """
            yield self[request_id]

    def __delitem__(self, request_id):
        """
        Delete a specific certificate request
        """
        os.unlink(SignRequest(request_id).path)

    def __getitem__(self, request_id):
        """
        Get a specific certificate request
        """

        with open(SignRequest(request_id).path, 'r') as stream:
            request_data = json.load(
                    stream,
            )

            requester = request_data.get('userName', None) or request_data.get('hostName', None)
            root_requested = request_data.get('rootRequested', False)
            key_data = request_data.get('keyData', None)

            values = request_data['request'].values()

            if 'ssh_user' in values:
                return UserSSHRequest(
                        request_id,
                        requester,
                        root_requested,
                        key_data,
                        )

            elif 'ssh_host' in values:
                return HostSSHRequest(
                        request_id,
                        requester,
                        key_data,
                        )

            elif 'ssl_host' in values:
                return HostSSLRequest(
                        request_id,
                        requester,
                        key_data,
                        )
            else:
                return SignRequest(request_id)

    @property
    def ssh(self):
        pass

    @property
    def ssl(self):
        pass

class CertificateLookup(object):
    """
    Proxy to interact with certificates
    """
    def __iter__(self):
        self.cert_dir = OUTPUT_PATH

    def __getitem__(self, certificate_id):
        """
        Get a specific certificate from disk
        """
        if not Certificate(certificate_id):
            raise IndexError

        return Certificate(certificate_id)

    def __iter__(self):
        """
        Iterate over all certificate request in OUTPUT_PATH
        """
        pass
