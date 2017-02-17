#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import hashlib
import json
import os
import os.path
import pickle
import shutil
import sqlite3
import tempfile

from models.authority import *
from models.certificate import *
from models.request import *
from paths import *

__doc__= """
Define proxy classes
"""

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
        authorities_path = os.path.join(self.path, 'pickled_cas')

        auth = []

        for authority in os.listdir(authorities_path):

            pickle_path = os.path.join(self.path, 'pickled_cas', authority)

            with open(pickle_path, 'rb') as stream:
                auth.append(pickle.load(stream))

        return iter(auth)

    def __getitem__(self, ca_id):

        if SSHAuthority(ca_id):

            return SSHAuthority(ca_id)

        elif SSLAuthority(ca_id):

            return SSLAuthority(ca_id)

        else:
            raise IndexError('Unknown CA "%s"' % ca_id)

    def __setitem__(self, ca_id, authority_class):
        """
        Create a new certification authority
        """

        if authority_class not in self.allowed_auth:

            raise ValueError('CA type is not supported')

        else:

            if not authority_class(ca_id):
                authority_class(ca_id).generate()

            else:
                raise ValueError('CA %s already exists' % ca_id)

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

        req_objs = []

        for request_id in os.listdir(self.request_dir):
            """
            request_id is formatted as uuid
            """
            with RequestLoader(request_id) as request:

                req_objs.append(request)

        return iter(req_objs)

    def __delitem__(self, request_id):
        """
        Delete a specific certificate request
        """
        os.unlink(SignRequest(request_id).path)

    def __getitem__(self, request_id):
        """
        Get a specific certificate request
        """
        if not SignRequest(request_id):
            raise IndexError

        with RequestLoader(request_id) as request:
            return request

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
