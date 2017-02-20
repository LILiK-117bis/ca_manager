#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import os.path
import sqlite3
import subprocess
import json

from paths import *

__doc__= """
Module of classes to handle certificate requests
"""

class SignRequest(object):
    def __init__(self, req_id):
        self.req_id = req_id

    def __repr__(self):
        return ( "%s %s" % ( str(self.__class__.__name__), str(self.req_id) ) )

    def __bool__(self):
        return os.path.exists(self.path)

    @property
    def name(self):
        raise NotImplementedError()

    @property
    def fields(self):
        raise NotImplementedError()

    @property
    def path(self):
        return os.path.join(REQUESTS_PATH, self.req_id)

    @property
    def destination(self):
        return os.path.join(OUTPUT_PATH, self.req_id + '.pub')

class RequestLoader(object):
    """
    Context manager that loads a request from a file
    and return a Request type
    """

    def __init__(self, request_id):
        self.request_id = request_id
        self.request_dir = REQUESTS_PATH

    @property
    def path(self):
        return os.path.join(self.request_dir, self.request_id)

    def __enter__(self):
        with open(self.path, 'r') as stream:
            request_data = json.load(
                stream,
            )

            requester = request_data.get('userName', None) or request_data.get('hostName', None)
            root_requested = request_data.get('rootRequested', False)
            key_data = request_data.get('keyData', None)

            # attribute cannot be read from
            # json, must add after decoding
            request_id = self.request_id

            values = request_data.values()

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
                # ultimate error, cannot be decoded
                return SignRequest(request_id)
    
    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            print(exc_type, exc_value)
            print(traceback)


    @property
    def fields(self):
        return [
            ("Hostname", self.host_name)
        ]
