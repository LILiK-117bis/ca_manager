#! /usr/bin/env python3

from setuptools import setup

setup(
    name='ca_manager',
    version='0.3.1',
    description='shell interface for certification authority management',
    author='LILiK',
    url='https://github.com/LILiK-117bis/ca_manager',
    license='GPL3',
    packages=[
        'ca_manager',
        'ca_manager.models',
        'ca_manager.openssl-config'
    ],
    package_data={'ca_manager': ['openssl-config/*.cnf']},
    install_requires=[
        'fqdn',
        'peewee<3',
    ],
    scripts=[
        'bin/ca-server',
        'bin/ca-shell',
    ],
    zip_safe=False,
    test_suite='nose.collector',
    tests_require=['nose']
)
