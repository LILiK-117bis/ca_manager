#! /usr/bin/env python3

from setuptools import setup

setup(
    name='ca_manager',
    version='0.1',
    description='shell interface for certification authority management',
    author='LILiK',
    url='https://github.com/LILiK-117bis/ca_manager',
    license='GPL3',
    packages=[
        'ca_manager',
        'ca_manager.models',
    ],
    install_requires=[
        'fqdn',
        'peewee',
    ],
    scripts=[
        'bin/ca-server',
        'bin/ca-shell',
    ],
    package_data={
        'ca_manager.models': [
            'openssl-config/*.cnf',
        ,
    },
    zip_safe=False
)
