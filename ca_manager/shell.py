#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import cmd
import sys
from datetime import datetime

from ca_manager.models.ssh import SSHAuthority
from ca_manager.models.ssl import SSLAuthority

from ca_manager.manager import sign_request

__doc__ = """
Class to make a shell and interact with the user
"""


class CAManagerShell(cmd.Cmd):
    intro = """# LILiK CA Manager #
    Welcome to the certification authority shell.
    Type help or ? to list commands.
    """
    prompt = "(CA Manager)> "

    def __init__(self, ca_manager):
        super(CAManagerShell, self).__init__()
        self.ca_manager = ca_manager

    def do_ls_cas(self, l):
        'List the available certification authorities: LS_CA'
        for i, authority in enumerate(self.ca_manager.ca):
            print(authority)

    def do_ls_certificates(self, l):
        'List the issued certificates: LS_CERTIFICATES'
        for i, cert in enumerate(self.ca_manager.certificate):
            print(cert)

    def do_ls_requests(self, l):
        'List the available certification requests: LS_REQUESTS'
        print_available_requests(self.ca_manager)

    def do_describe_ca(self, l):
        'Show certification authority information: DESCRIBE_CA ca_id'
        argv = l.split()
        argc = len(argv)

        # argument number is too low
        if argc < 1:
            print("Usage: DESCRIBE_CA ca_id")
            return

        ca = self.ca_manager.ca[argv[0]]

        if ca:
            ca_description = """
            Certification authority: %s
            --------------------------------------------------
            CA type: %s
            CA name: %s
            Serial: %s
            """

            ca_info = (
                    ca.ca_id,
                    ca.__class__.__name__,
                    ca.name,
                    ca.serial,
                    )

            print(ca_description % ca_info)
        else:
            print("No CA found for id: '%s'" % argv[0])

    def do_describe_certificate(self, l):
        'Show certificate information: DESCRIBE_CERTIFICATE request_id'
        argv = l.split()
        argc = len(argv)

        # argument number is too low
        if argc < 1:
            print("Usage: DESCRIBE_CERTIFICATE request_id")
            return

        cert = self.ca_manager.certificate[argv[0]]

        if cert:
            cert_description = """
            Certificate %s
            --------------------------------------------------
            Signin authority: %s
            Signed on: %s
            Receiver: %s
            Certificate Serial: %s
            Validity Interval: %s
            Revoked: %s
            """

            cert_info = (
                    cert.cert_id,
                    cert.signed_by,
                    cert.date_issued,
                    cert.receiver,
                    cert.serial_number,
                    cert.validity_interval,
                    cert.revoked,
                    )

            print(cert_description % cert_info)
        else:
            print('No certificate found for id: "%s"' % argv[0])
        pass

    def do_describe_request(self, l):
        'Show sign request information: DESCRIBE_REQUEST request_id'
        argv = l.split()
        argc = len(argv)

        # argument number is too low
        if argc < 1:
            print("Usage: DESCRIBE_REQUEST request_id")
            return

        request = self.ca_manager.request[argv[0]]

        if request:
            request_description = """
            Request %s
            --------------------------------------------------
            Request type: %s
            %s
            Key %s
            """

            request_info = (
                    request.req_id,
                    request.__class__.__name__,
                    request.fields,
                    request.key_data,
                    )

            print(request_description % request_info)
        else:
            print('No request found for id: "%s"' % argv[0])

    def do_drop_request(self, l):
        'Delete a sign request: DROP_REQUEST request_id'
        argv = l.split()
        argc = len(argv)

        # argument number is too low
        if argc < 1:
            print("Usage: DROP_REQUEST request_id")
            return

        for item in argv:
            del self.ca_manager.request[item]

    def do_gen_ssh(self, l):
        'Generate a SSH Certification authority: GEN_SSH ca_id ca_description'
        argv = l.split(maxsplit=1)
        argc = len(argv)

        # argument number is too low
        if argc < 2:
            print("Usage: GEN_SSH ca_id ca_description")
            return

        ca_id = argv[0]
        name = argv[1]
        new_auth = SSHAuthority(
                ca_id=ca_id,
                name=name,
                serial=0,
                active=True,
                creation_date=datetime.now(),
                )

        new_auth.generate()
        new_auth.save()

    def do_gen_ssl(self, l):
        'Generate a SSL Certification authority: GEN_SSL ca_id ca_description'
        argv = l.split(maxsplit=1)
        argc = len(argv)

        # argument number is too low
        if argc < 2:
            print("Usage: gen_ssl ca_id ca_description")
            return

        ca_id = argv[0]
        name = argv[1]
        new_auth = SSLAuthority(
                ca_id=ca_id,
                name=name,
                serial=0,
                active=True,
                creation_date=datetime.now(),
                )

        new_auth.generate()
        new_auth.save()

    def do_sign_request(self, l):
        'Sign a request using a CA: SIGN_REQUEST ca_id request_id'
        argv = l.split()
        argc = len(argv)

        # argument number is too low
        if argc < 2:
            if argc == 0:
                # print available ca
                print("Available authority")
                print_available_authorities(self.ca_manager)

                print("==================")

                # print available requests
                print("Available request")
                print_available_requests(self.ca_manager)
        else:
            authority_id, request_id = argv[0], argv[1]

            sign_request(self.ca_manager, request_id, authority_id)

    def do_revoke_certificates(self, l):
        'Revoke the issued certificates: REVOKE_CERTIFICATE certificate_id ...'
        argv = l.split()
        argc = len(argv)

        # argument number is too low
        if argc < 1:
            print("Usage: REVOKE_CERTIFICATE certificate_id ...")

        for item in argv:
            cert = self.ca_manager.certificate[item]
            cert.revoked = True
            cert.save()

    def common_complete_request(self, text, line, begidx, endidx, check_argc=2):
        argv = ("%send" % line).split()
        argc = len(argv)
        if check_argc is None or argc == check_argc:
            return [request.req_id for i, request in enumerate(self.ca_manager.request) if request.req_id.startswith(text) and request.req_id not in argv[1:]]

    def common_complete_ca(self, text, line, begidx, endidx, check_argc=2):
        argc = len(("%send" % line).split())
        if check_argc is None or argc == check_argc:
            return [ca_item.ca_id for i, ca_item in enumerate(self.ca_manager.ca) if ca_item.ca_id.startswith(text)]

    def common_complete_certificate(self, text, line, begidx, endidx, check_argc=2):
        argc = len(("%send" % line).split())
        if check_argc is None or argc == check_argc:
            return [certificate.cert_id for i, certificate in enumerate(self.ca_manager.certificate) if certificate.cert_id.startswith(text)]

    def complete_drop_request(self, text, line, begidx, endidx):
        return self.common_complete_request(text, line, begidx, endidx, None)

    def complete_describe_certificate(self, text, line, begidx, endidx):
        return self.common_complete_certificate(text, line, begidx, endidx)

    def complete_describe_ca(self, text, line, begidx, endidx):
        return self.common_complete_ca(text, line, begidx, endidx)

    def complete_describe_request(self, text, line, begidx, endidx):
        return self.common_complete_request(text, line, begidx, endidx)

    def complete_sign_request(self, text, line, begidx, endidx):
        results = ''
        argc = len(("%send" % line).split())

        if argc == 2:
            results = [ca_item.ca_id for i, ca_item in enumerate(self.ca_manager.ca) if ca_item.ca_id.startswith(text)]
        elif argc == 3:
            try:
                ca = self.ca_manager.ca[line.split()[1]]
            except Exception as e:
                print("Error: %s" % e)
                return

            results = [request.req_id for i, request in enumerate(self.ca_manager.request) if request.req_id.startswith(text) and request.__class__ in ca.request_allowed]
        return results

    def complete(self, text, state):
        results = super().complete(text, state)
        if results is not None:
            return "%s " % results
        return results

    def do_quit(self, l):
        'Quit this shell'
        return True


def print_available_authorities(ca_manager):
    for i, ca in enumerate(ca_manager.ca):
        print(ca)


def print_available_requests(ca_manager):
    for i, request in enumerate(ca_manager.request):
        print(request)
