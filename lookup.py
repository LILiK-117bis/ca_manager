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
    Proxy to interact with the database, get CA as element or as list
    """
    def __init__(self, ssh_ca_dir, ssl_ca_dir):
        """
        The connection attribute is setted by the CAManager instance
        when used
        """

        self.conn = None
        self.ssh_ca_dir = ssh_ca_dir
        self.ssl_ca_dir = ssl_ca_dir

    def __iter__(self):
        c = self.conn.cursor()

        c.execute("""SELECT id, name, type FROM cas""")

        return iter(c.fetchall())

    def __delitem__(self, ca_id):
        """
        Delete a specific certification authority from the database
        """
        c = self.conn.cursor()
        c.execute("""DELETE FROM cas WHERE id = ?""", (ca_id, ))

    def __getitem__(self, ca_id):
        """
        Get a specific certification authority from the database
        """
        c = self.conn.cursor()
        c.execute("""SELECT name, type FROM cas WHERE id = ?""", (ca_id, ))

        result = c.fetchone()
        if not result:
            raise IndexError('Unknown CA "%s"' % ca_id)

        ca_name, ca_type = result

        if ca_type.lower() == 'ssh':
            return SSHAuthority(ca_id, ca_name, self.ssh_ca_dir)

        elif ca_type.lower() == 'ssl':
            return SSLAuthority(ca_id, ca_name, self.ssl_ca_dir)

    def __setitem__(self, ca_id, ca_value):
        """
        Create a new certification authority, insert
        it into the database
        """
        ca_name, ca_type = ca_value
        authority = None

        if ca_type.lower() == 'ssh':
            authority = SSHAuthority(ca_id, ca_name, self.ssh_ca_dir)
        elif ca_type.lower() == 'ssl':
            authority = SSLAuthority(ca_id, ca_name, self.ssl_ca_dir)
        else:
            raise ValueError('CA type is not supported')

        authority.generate()

        c = self.conn.cursor()
        c.execute("""INSERT INTO cas VALUES (?, ?, ?)""",
                (ca_id, ca_name, ca_type.lower()))
        self.conn.commit()

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
        os.unlink(os.path.join(self.request_dir, request_id))

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
