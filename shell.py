#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import sys
from datetime import datetime

from models.ssh import SSHAuthority
from models.ssl import SSLAuthority

from manager import sign_request

__doc__= """
        Class to make a shell and interact with the user
        """

class CAManagerShell(cmd.Cmd):
    intro= """# LILiK CA Manager #
    Welcome to the certification authority shell.
    Type help or ? to list commands.
    """
    prompt= "(CA Manager)> "

    def __init__(self, ca_manager):
        super(CAManagerShell, self).__init__()
        self.ca_manager = ca_manager

    def do_ls_cas(self, l):
        'List the available certification authorities: LS_CA'
        for i, authority in enumerate(self.ca_manager.ca):
            print('- %d - %s' % (i, authority))

    def do_ls_certificates(self, l):
        'List the issued certificates: LS_CERTIFICATE'
        for i, cert in enumerate(self.ca_manager.certificate):
            print('- %d - %s' % (i, cert))

    def do_ls_requests(self, l):
        'List the available certification requests: LS_REQUESTS'
        print_available_requests(self.ca_manager)

    def do_describe_ca(self, l):
        'Show certification authority information: DESCRIBE_CA'
        ca_id = l.split()[0]

        ca = self.ca_manager.ca[ca_id]

        if ca:
            ca_description = """
            Certification authority: %s
            --------------------------------------------------
            CA type: %s
            CA name: %s
            Serial: %s
            """

            ca_info = (
                    ca_id,
                    ca.__class__.__name__,
                    ca.name,
                    ca.serial,
                    )

            print(ca_description % ca_info)
        else:
            print("No CA found for id: '%s'" % request_id)

    def do_describe_certificate(self, l):
        'Show certificate information: DESCRIBE_CERTIFICATE'
        certificate_id = l.split()[0]

        cert = self.ca_manager.certificate[certificate_id]

        if cert:
            cert_description = """
            Certificate %s
            --------------------------------------------------
            Signin authority: %s
            Signed on: %s
            Receiver: %s
            Certificate Serial: %s
            Validity Interval: %s
            """

            request_info = (
                    certificate_id,
                    cert.signed_by,
                    cert.date_issued,
                    cert.receiver,
                    cert.serial_number,
                    cert.validity_interval,
                    )

            print(cert_description % cert_info)
        else:
            print('No certificate found for id: "%s"' % cert_id)
        pass

    def do_describe_request(self, l):
        'Show sign request information: DESCRIBE_REQUEST'
        request_id = l.split()[0]

        request = self.ca_manager.request[request_id]

        if request:
            request_description = """
            Request %s
            --------------------------------------------------
            Request type: %s
            %s
            Key %s
            """

            request_info = (
                    request_id,
                    request.__class__.__name__,
                    request.fields,
                    request.key_data,
                    )

            print(request_description % request_info)
        else:
            print('No request found for id: "%s"' % request_id)

    def do_drop_request(self, l):
        'Delete a sign request: DROP_REQUEST'
        request_id = l.split()[0]

        del self.ca_manager.request[request_id]

    def do_gen_ssh(self, l):
        'Generate a SSH Certification authority: GEN_SSH id name'
        argv = l.split(maxsplit=1)
        ca_id = argv[0]
        name = argv[1]
        new_auth = SSHAuthority(
                ca_id = ca_id,
                name = name,
                serial = 0,
                active = True,
                creation_date = datetime.now(),
                )

        new_auth.generate()
        new_auth.save()

    def do_gen_ssl(self, l):
        'Generate a SSL Certification authority'
        argv = l.split(maxsplit=1)
        ca_id = argv[0]
        name = argv[1]
        new_auth = SSLAuthority(
                ca_id = ca_id,
                name = name,
                serial = 0,
                active = True,
                creation_date = datetime.now(),
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
            authority_id, request_id  = argv[0], argv[1]

            sign_request(self.ca_manager, request_id, authority_id)

    def common_complete_request(self, text, line, begidx, endidx):
        argc = len(("%send"%line).split())
        if argc == 2:
            return [request.req_id for i, request in enumerate(self.ca_manager.request) if request.req_id.startswith(text)]

    def complete_drop_request(self, text, line, begidx, endidx):
        return self.common_complete_request(text, line, begidx, endidx)


    def complete_describe_request(self, text, line, begidx, endidx):
        return self.common_complete_request(text, line, begidx, endidx)

    def complete_sign_request(self, text, line, begidx, endidx):
        results = ''
        argc = len(("%send"%line).split())

        if argc == 2:
            results = [ca_item.ca_id for i, ca_item  in enumerate(self.ca_manager.ca) if ca_item.ca_id.startswith(text)]
        elif argc == 3:
            try:
                ca = self.ca_manager.ca[line.split()[1]]
            except Exception as e:
                print ("Error: %s"%e)
                return

            results = [request.req_id for i, request in enumerate(self.ca_manager.request) if request.req_id.startswith(text) and request.__class__ in ca.compatible_requests]
        return results

    def complete(self, text, state):
        results = super().complete(text, state)
        if results is not None:
            return "%s "%results
        return results

    def do_quit(self, l):
        'Quit this shell'
        return True


def print_available_authorities(ca_manager):
    for i, ca_item  in enumerate(ca_manager.ca):
        print("- %d : %s" % (i , ca_item))

def print_available_requests(ca_manager):
    for i, request in enumerate(ca_manager.request):
        print("- %d : %s" % (i, request))
