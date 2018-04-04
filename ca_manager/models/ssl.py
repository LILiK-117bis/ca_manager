#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from playhouse.gfk import *

import os
from inspect import getsourcefile
import subprocess

from .authority import Authority
from .certificate import Certificate
from .request import SignRequest
from ..paths import *

import json

import getpass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import datetime

def create_root_ca(issuer, issuer_key, validity):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(issuer)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(issuer_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity))
    builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True)
    builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False)
    builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),
            critical=False)
    builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint([x509.UniformResourceIdentifier("http://127.0.0.1/%s.crl"%issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)], None, None, None)
            ]),
            critical=True)
    return builder.sign(issuer_key, hashes.SHA256(), default_backend())


def create_csr(subject, subject_key, is_ca=False):
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    if is_ca:
        builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True)
    builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False)
    return builder.sign(subject_key, hashes.SHA256(), default_backend())


def sign_csr(csr, issuer_cert, issuer_key, validity):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity))
    builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False)
    builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint([x509.UniformResourceIdentifier("http://127.0.0.1/%s.crl"%issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)], None, None, None)
            ]),
            critical=True)
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, critical=extension.critical)
    return builder.sign(issuer_key, hashes.SHA256(), default_backend())

def write_key(key, path, password):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
            ))

def write_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def write_crl(crl, path):
    with open(path, "wb") as f:
        f.write(crl.tbs_certlist_bytes())


class HostSSLRequest(SignRequest):
    def __init__(self, req_id, host_name, key_data):
        super().__init__(req_id)

        self.host_name = host_name
        self.key_data = key_data

    @property
    def name(self):
        return 'Hostname: %s' % self.host_name

    @property
    def fields(self):
        return [
            ('Hostname', self.host_name)
        ]

    @property
    def receiver(self):
        return self.host_name


class UserSSLRequest(SignRequest):
    def __init__(self, req_id, user_name, key_data):
        super().__init__(req_id)

        self.user_name = user_name
        self.key_data = key_data

    @property
    def name(self):
        return 'User: {}'.format(self.user_name)

    @property
    def fields(self):
        return [
            ('User name', self.user_name)
        ]

    @property
    def receiver(self):
        return self.user_name


class CASSLRequest(SignRequest):
    def __init__(self, req_id, ca_name, key_data):
        super().__init__(req_id)

        self.ca_name = ca_name
        self.key_data = key_data

    @property
    def name(self):
        return 'CA name: %s' % self.ca_name

    @property
    def fields(self):
        return [
            ('CA name', self.ca_name)
        ]

    @property
    def receiver(self):
        return self.ca_name


class SSLAuthority(Authority):
    request_allowed = [
        HostSSLRequest,
        UserSSLRequest,
        CASSLRequest,
    ]

    key_length = 4096

    root_ca_validity = 10 * 365
    ca_validity = 5 * 1825
    cert_validity = 365

    def generate(self, isRoot=None, password=None):
        if os.path.exists(self.path):
            raise ValueError('A CA with the same id and type already exists')
        if isRoot != None:
            self.isRoot = isRoot
        else:
            confirm = input('Is a root CA? [y/N]> ')
            if confirm == 'y':
                self.isRoot = True
            else:
                self.isRoot = False
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096,
            backend=default_backend())
        if password == None:
            password = getpass.getpass('Insert CA passord:')
        write_key(ca_key, '%s' % (self.path), password.encode('UTF-8'))

        if self.isRoot:
            ca_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tuscany"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Florence"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LILiK"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.name),
                ])
            ca_cert = create_root_ca(issuer=ca_subject, issuer_key=ca_key, validity=self.root_ca_validity)
            write_cert(ca_cert, '%s.pub' % self.path)
        else:
            int_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tuscany"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Florence"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LILiK"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.name),
                ])
            int_csr = create_csr(int_subject, ca_key, is_ca=True)
            write_cert(int_csr, '%s.csr' % self.path)
            result_dict = {}
            result_dict['keyType'] = 'ssl_ca'
            result_dict['caName'] = self.ca_id
            with open("%s.csr" % self.path, 'r') as f:
                result_dict['keyData'] = "".join(f.readlines())

            request = {'type': 'sign_request', 'request': result_dict}
            print('Please sign the following request:')
            print(json.dumps(request))

        if not self.isRoot:
            return request

    def generate_certificate(self, request, password=None):
        """
        Sign a *SSLRequest with this certification authority
        """

        if not os.path.exists('%s.pub' % self.path) and not self.isRoot:
            raise ValueError("The CA certificate '%s.pub' doesn't exists yet" % self.path)

        if password == None:
            password = getpass.getpass('Insert CA passord:')

        pub_key_path = request.destination
        cert_path = request.cert_destination

        with open(pub_key_path, 'w') as stream:
            stream.write(request.key_data)

        with open(self.path, 'rb') as f:
            ca_key_data = f.read()
        ca_key = load_pem_private_key(ca_key_data, password.encode('UTF-8'), default_backend())
        with open('%s.pub' % self.path, 'rb') as f:
            ca_cert_data = f.read()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
        with open(request.destination, 'rb') as f:
            request_key_data = f.read()
        csr = x509.load_pem_x509_csr(request_key_data, default_backend())
        validity = self.cert_validity
        for extension in csr.extensions:
            if extension.value.ca:
                break
        else:
            validity = self.ca_validity
        cert = sign_csr(csr, ca_cert, ca_key, validity)
        write_cert(cert, cert_path)

        with open(cert_path, 'a') as cert_file:
            with open('%s.pub' % self.path) as ca_cert_file:
                cert_file.writelines(ca_cert_file.readlines())
        return {'validity': validity, 'serial_number': cert.serial_number}

    def generate_crl(self, password=None):
        if password == None:
            password = getpass.getpass('Insert CA passord:')

        from cryptography.x509.oid import NameOID
        import datetime
        one_day = datetime.timedelta(1, 0, 0)

        with open(self.path, 'rb') as f:
            ca_key_data = f.read()
        ca_key = load_pem_private_key(ca_key_data, password.encode('UTF-8'), default_backend())
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ]))
        builder = builder.last_update(datetime.datetime.today())
        builder = builder.next_update(datetime.datetime.today() + one_day)
        for certificate in self.signed_certificates.where(Certificate.revoked):
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                int(certificate.serial_number)
            ).revocation_date(
                datetime.datetime.today()
            ).build(default_backend())
            builder = builder.add_revoked_certificate(revoked_cert)
        crl = builder.sign(
            private_key=ca_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        with open("%s.crl"%self.path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
