#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os.path

from ..paths import *

__doc__ = """
Module of classes to handle sign requests
"""


class SignRequest(object):
    def __init__(self, req_id):
        self.req_id = req_id

    def __repr__(self):
        return ('%s %s with fields: %s' % (self.__class__.__name__, self.req_id, self.fields))

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

    @property
    def cert_destination(self):
        return os.path.join(OUTPUT_PATH, self.req_id + '-cert.pub')

    @property
    def fields(self):
        return [
            ('Hostname', self.host_name)
        ]
