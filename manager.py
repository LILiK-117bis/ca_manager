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

from paths import *
from lookup import CALookup, RequestLookup, CertificateLookup

__doc__= """
Define classes to interact with certificate requests and Certification Authority
"""

class CAManager(object):
    """
    Middleware to interact with ssh-keygen
    """

    def __init__(self, path):
        self.path = path
        self.ca = CALookup()
        self.request = RequestLookup()
        self.certificate = CertificateLookup()

    def __enter__(self):
        """
        Enter a context block, connect to database
        """
        self.conn = sqlite3.connect(self.db_path)
        self.ca.conn = self.conn

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exit a context block, disconnect from database
        """
        if exc_type is not None:
            print(exc_type, exc_value)
            print(traceback)

        self.ca.conn = None
        self.conn.close()

    @property
    def db_path(self):
        return os.path.join(self.path, 'ca_manager.db')

    @property
    def ssh_ca_dir(self):
        return os.path.join(self.path, 'ssh_cas')

    @property
    def ssl_ca_dir(self):
        return os.path.join(self.path, 'ssl_cas')

def init_manager(paths):
    """
    Initiate the manager by creating the
    directories to store CAs and requests.

    Create a database to store the information
    """
    db_path = os.path.join(paths[0], 'ca_manager.db')

    directories = ['ssh_cas', 'ssl_cas', 'pickled_cas',]

    # ensure the directories needed by CAManager
    # exists
    for dirpath in paths:
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)

    # ensure ssh_cas ad ssl_cas directories
    # exists in MANAGER_PATH
    for dirname in directories:
        dirpath = os.path.join(paths[0], dirname)

        if not os.path.exists(dirpath):
            os.mkdir(dirpath)

    # ensure the database exists
    # in MANAGER_PATH
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE cas (id text, name text, type text)""")
        conn.commit()
        conn.close()

def sign_request(ca_manager, request_id, authority_id):

    authority, request = None, None

    try:
        authority = ca_manager.ca[authority_id]
    except IndexError:
        print("Could not find CA '%d'" % authority_id)
        return

    try:
        request = ca_manager.request[request_id]
    except IndexError:
        print("Could not find request '%d'" % request_id)

    h = hashlib.sha256()
    h.update(request.key_data.encode('utf-8'))
    print("Request hash: %s" % h.hexdigest())

    print("You are about to sign this request with the following CA:")
    confirm = input('Proceed? (type yes)> ')
    if confirm != 'yes':
        print ("user abort")
        return

    cert_path = authority.sign(request)
    del ca_manager.request[request_id]

    shutil.copy(cert_path, os.path.join(RESULTS_PATH, request.req_id))


if __name__ == '__main__':
    from ca_shell import CAManagerShell

    init_manager([
        MANAGER_PATH,
        REQUESTS_PATH,
        OUTPUT_PATH,
        RESULTS_PATH,
        ])


    with CAManager(MANAGER_PATH) as ca_manager:

        CAManagerShell(ca_manager).cmdloop()