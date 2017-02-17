#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json

from paths import *

__doc__= """
Module of classes to handle certificate requests
"""

class Certificate(object):
    def __init__(self, cert_id):
        self.cert_id = cert_id

    def __repr__(self):
        return ( "%s %s" % ( str(self.__class__.__name__), str(self.cert_id) ) )

    def __bool__(self):
        return os.path.exists(self.path)

    @property
    def path(self):
        return os.path.join(OUTPUT_PATH, self.cert_id + '-cert.pub')
