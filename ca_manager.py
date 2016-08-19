#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import hashlib
import json
import os
import os.path
import shutil
import sqlite3
import subprocess
import tempfile

from certificate_requests import *
from paths import *



class CAManager(object):
    """
    Middleware to interact with ssh-keygen
    """
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        """
        Enter a context block, connect to database
        """
        self.conn = sqlite3.connect(self._get_db_path())

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exit a context block, disconnect from database
        """
        if exc_type is not None:
            print(exc_type, exc_value)
            print(traceback)

        self.conn.close()

    def _get_db_path(self):
        return os.path.join(self.path, 'ca_manager.db')

    def _get_ssh_cas_dir(self):
        return os.path.join(self.path, 'ssh_cas')

    def _get_ssh_ca_path(self, ca_id):
        cas_dir = self._get_ssh_cas_dir()
        return os.path.join(cas_dir, ca_id)

    def _get_ssl_cas_dir(self):
        return os.path.join(self.path, 'ssl_cas')

    def _get_ssl_ca_path(self, ca_id):
        cas_dir = self._get_ssl_cas_dir()
        return os.path.join(cas_dir, ca_id)

    def create_ssh_ca(self, ca_id, ca_name):
        """
        Create a new ssh certification authority, insert
        it into the database
        """
        ca_path = self._get_ssh_ca_path(ca_id)

        authority = SSHAuthority(ca_id, ca_name, ca_path)

        authority.generate()

        c = self.conn.cursor()
        c.execute("""INSERT INTO cas VALUES (?, ?, 'ssh')""",
                (ca_id, ca_name))
        self.conn.commit()

    def create_ssl_ca(self, ca_id, ca_name):
        """
        Create a new ssl certification authority, insert
        it into the database
        """
        ca_path = self._get_ssl_ca_path(ca_id)

        authority = SSLAuthority(ca_id, ca_name, ca_path)

        authority.generate()

        c = self.conn.cursor()
        c.execute("""INSERT INTO cas VALUES (?, ?, 'ssl')""",
                (ca_id, ca_name))
        self.conn.commit()

    def get_cas_list(self):
        """
        Get all the certification authorities saved in
        the database
        """
        c = self.conn.cursor()

        c.execute("""SELECT id, name, type FROM cas""")

        return c.fetchall()

    def get_ca(self, ca_id):
        """
        Get a specific certification authority from the database
        """
        c = self.conn.cursor()
        c.execute("""SELECT name, type FROM cas WHERE id = ?""", (ca_id, ))

        ca_name, ca_type = c.fetchone()

        if ca_type == 'ssh':
            ca_path = self._get_ssh_ca_path(ca_id)
            return SSHAuthority(ca_id, ca_name, ca_path)
        elif ca_type == 'ssl':
            ca_path = self._get_ssl_ca_path(ca_id)
            return SSLAuthority(ca_id, ca_name, ca_path)

    def get_requests(self):

        req_objs = []

        for request_name in os.listdir(REQUESTS_PATH):
            request_path = os.path.join(REQUESTS_PATH, request_name)

            with open(request_path, 'r') as stream:
                req = json.load(stream)

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


def main():
    global MANAGER_PATH

    init_manager([MANAGER_PATH, REQUESTS_PATH, OUTPUT_PATH, RESULTS_PATH])

    menu_entries = [
        ("list-cas", "List available CAs"),
        ("show-ca", "Show CA info"),
        ("gen-ssh-ca", "Generate SSH CA"),
        ("gen-ssl-ca", "Generate SSL CA"),
        ("sign-request", "Sign request"),
        ("help", "Show this message"),
        ("quit", "Quit from CA manager")
    ]

    with CAManager(MANAGER_PATH) as ca_manager:

def list_cas(ca_manager):
    for ca_id, ca_name, ca_type in ca_manager.get_cas_list():
        print("- [%3s] %-15s (%s)" % (ca_type, ca_id, ca_name))


def sign_request(ca_manager):
    global RESULTS_PATH

    list_cas(ca_manager)
    ca_selection = input('Select a CA> ')

    try:
        authority = ca_manager.get_ca(ca_selection)
    except:
        print("Could not find CA '%s'" % ca_selection)
        return

    requests = ca_manager.get_requests()
    for i, request in enumerate(requests):
        print("%2d) %s - %s" % (i, request.req_id, request.get_name()))
    req_selection = input('Select a request> ')

    try:
        req_selection = int(req_selection)
        req_obj = requests[req_selection]
    except:
        return

    print("Request details:")
    for field_name, field_value in req_obj.get_fields():
        print("- %s: %s" % (field_name, field_value))

    h = hashlib.sha256()
    h.update(req_obj.key_data.encode('utf-8'))
    print("Request hash: %s" % h.hexdigest())

    print("You are about to sign this request with the following CA:")
    print("- %s (%s)" % (authority.ca_id, authority.name))
    confirm = input('Proceed? (type yes)> ')
    if confirm != 'yes':
        return

    cert_path = authority.sign(request)
    ca_manager.drop_request(request)

    shutil.copy(cert_path, os.path.join(RESULTS_PATH, request.req_id))


if __name__ == '__main__':
    main()
