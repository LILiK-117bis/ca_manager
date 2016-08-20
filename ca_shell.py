#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import sys

from ca_manager import list_cas, sign_request

class CAManagerShell(cmd.Cmd, object):
    intro= """# LILiK CA Manager\n
    Welcome to the certification authority shell.
    Type help or ? to list commands.
    """
    prompt= "(CA Manager)> "

    def __init__(self, ca_manager):
        super(CAManagerShell, self).__init__()
        self.ca_manager= ca_manager

    def do_ls_ca(self, l):
        'List the available certification authorities: LS_CA'
        list_cas(self.ca_manager)

    def do_ls_requests(self, l):
        'List the available certification requests: LS_REQUESTS'
        print_available_requests(self.ca_manager)

    def do_describe_cas(self, l):
        'Show certification authority information: DESCRIBE_CAS'
        raise NotImplementedError

    def do_gen_ca(self, l):
        'Generate a certification authority: GEN_CA type id name'
        argv = l.split()
        argc = len(argv)
        try:
            if argc > 3:
                raise(ValueError)

            if argc < 1:
                ca_type = input("CA type> ")
            else:
                ca_type = argv[0]

            if argc < 2:
                ca_id = input("CA unique id> ")
            else:
                ca_name = argv[1]

            if argc < 3:
                ca_name = input("CA human-readable name> ")
            else:
                ca_name = argv[2]

        except ValueError:
            print("Malformed input: %s" % l)
            return

        if ca_type == "ssl":
            self.ca_manager.create_ssl_ca(ca_id, ca_name)
        elif ca_type == "ssh":
            self.ca_manager.create_ssh_ca(ca_id, ca_name)
        else:
            print("Invalid CA type: %s" % ca_type)
            return

    def complete_gen_ca(self, text, line, begidx, endidx):

        results = ''

        argc = len(("%send"%line).split())

        if argc == 2:
            results = [a for a in ["ssl", "ssh"] if a.startswith(text)]
        return results

    def do_sign_request(self, l):
        'Sign a request using a CA: SIGN_REQUEST ca_name request_id'
        argv = l.split()
        argc = len(argv)
        # argument number is too low
        if argc < 3:

            # print available ca
            print("Available authority")
            print_available_authorities(self.ca_manager)

            print("==================")

            # print available requests
            print("Available request")
            print_available_requests(self.ca_manager)

            print("==================")

            # print usage
            print("usage: sign_request autority request")
        else:
            # [request_number, authority_number] =
            authority_name = argv[0]
            request_name = " ".join(argv[1:])
            sign_request(self.ca_manager, request_name, authority_name)

    def complete_sign_request(self, text, line, begidx, endidx):
        results = ''
        argc = len(("%send"%line).split())

        if argc == 2:
            results = [a[0] for a in self.ca_manager.get_cas_list() if a[0].startswith(text)]
        elif argc == 3:
            results = [a for a in self.ca_manager.get_requests() if str(a).startswith(text)]
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
    for i, ca_item  in enumerate(ca_manager.get_cas_list()):
        (ca_id, ca_name, ca_type) = ca_item
        print("- %d : [%3s] %-15s (%s)" % (i ,ca_type, ca_id, ca_name))

def print_available_requests(ca_manager):
    requests = ca_manager.get_requests()
    if not requests:
        print("No requests")
    for i, request in enumerate(requests):
        print("- %d : %s" % (i, request))
