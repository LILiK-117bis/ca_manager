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
from lookup import CALookup, RequestLookup

__doc__= """
Define classes to interact with certificate requests and Certification Authority
"""

class CAManager(object):
    """
    Middleware to interact with ssh-keygen
    """

    def __init__(self, path):
        self.path = path
        self.ca = CALookup(self.ssh_ca_dir, self.ssl_ca_dir)
        self.request = RequestLookup()

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

    def get_requests(self, ca_type=None):

        req_objs = []

        for request_name in os.listdir(REQUESTS_PATH):
            request_path = os.path.join(REQUESTS_PATH, request_name)

            with open(request_path, 'r') as stream:
                req = json.load(stream)

            if ca_type and not req['keyType'].startswith("%s_"%ca_type):
                continue

            if req['keyType'] == 'ssh_user':
                user_name = req['userName']
                root_requested = req['rootRequested']
                key_data = req['keyData']

                req_objs.append(
                        UserSSHRequest(
                            request_name, user_name, root_requested, key_data))
            elif req['keyType'] == 'ssh_host':
                host_name = req['hostName']
                key_data = req['keyData']

                req_objs.append(
                        HostSSHRequest(
                            request_name, host_name, key_data))
            elif req['keyType'] == 'ssl_host':
                host_name = req['hostName']
                key_data = req['keyData']

                req_objs.append(
                        HostSSLRequest(
                            request_name, host_name, key_data))

        return req_objs

    def drop_request(self, request):

        os.unlink(os.path.join(REQUESTS_PATH, request.req_id))

def init_manager(paths):
    """
    Initiate the manager by creating the
    directories to store CAs and requests.

    Create a database to store the information
    """
    db_path = os.path.join(paths[0], 'ca_manager.db')

    directories = ['ssh_cas', 'ssl_cas']

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

def sign_request(ca_manager, request_name, authority_name):
    request = None

    try:
        authority = ca_manager.ca[authority_name]
    except IndexError:
        print("Could not find CA '%d'" % choosen_ca)
        return

    requests = ca_manager.get_requests()

    for i in requests:
        if str(i) == request_name:
            request = i
    if request is None:
        raise(IndexError)

    h = hashlib.sha256()
    h.update(request.key_data.encode('utf-8'))
    print("Request hash: %s" % h.hexdigest())

    print("You are about to sign this request with the following CA:")
    confirm = input('Proceed? (type yes)> ')
    if confirm != 'yes':
        print ("user aborT")
        return

    cert_path = authority.sign(request)
    ca_manager.drop_request(request)

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
