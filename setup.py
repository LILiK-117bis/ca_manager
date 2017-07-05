#! /usr/bin/env python3

from setuptools import setup

setup(
    name='camanager',
    version='0.1',
    description='shell interface for certification authority management',
    author='LILiK',
    url='https://github.com/LILiK-117bis/ca_manager',
    license='MIT',
    packages=['ca_manager'],
    install_requires=[
        'peewee',
    ],
    zip_safe=False
)
