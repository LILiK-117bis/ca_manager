#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import hashlib
import json
import os
import os.path
import shutil
import sqlite3
import tempfile

from authority import *
from certificate import *
from request import *
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

        """
        """

    def __getitem__(self, ca_id):





        """
        """

            raise ValueError('CA type is not supported')



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
