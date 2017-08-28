#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os

config = configparser.ConfigParser()

config.readfp(open('defaults.cfg'))
config.read(['ca_manager.cfg', os.path.expanduser('~/.ca_manager.cfg')])

MANAGER_PATH = config['PATHS']['manager_path']
REQUESTS_PATH = config['PATHS']['requests_path']
OUTPUT_PATH = config['PATHS']['output_path']
RESULTS_PATH = config['PATHS']['results_path']
REQUEST_USER_HOME = config['PATHS']['request_user_home']

__doc__ = """
Paths for directories used by the CA manager
"""
