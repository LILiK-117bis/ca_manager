#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import os
import os.path
import shutil
import subprocess

from playhouse.gfk import *

from .lookup import CALookup, RequestLookup, CertificateLookup

from .models.ssh import SSHAuthority
from .models.ssl import SSLAuthority
from .models.certificate import Certificate

from .paths import *

__doc__ = """
Define classes to interact with certificate
requests and Certification Authority
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

        # Create tables
        SSHAuthority.create_table(fail_silently=True)
        SSLAuthority.create_table(fail_silently=True)
        Certificate.create_table(fail_silently=True)

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
    directories = ['ssh_cas', 'ssl_cas', ]

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

    print("You are about to sign the following request:\n  %s\nwith the following CA:\n  %s"%(request, authority))
    confirm = input('Proceed? (type yes)> ')
    if confirm != 'yes':
        print("user abort")
        return

    try:
        cert_path = authority.sign(request)
        del ca_manager.request[request_id]

        shutil.copy(cert_path, os.path.join(RESULTS_PATH, request.req_id))
    except subprocess.CalledProcessError as e:
        print('Could not sign certificate request')
        print(e)


if __name__ == '__main__':
    from shell import CAManagerShell

    init_manager([
        MANAGER_PATH,
        REQUESTS_PATH,
        OUTPUT_PATH,
        RESULTS_PATH,
        ])

    ca_manager = CAManager(MANAGER_PATH)

    CAManagerShell(ca_manager).cmdloop()
