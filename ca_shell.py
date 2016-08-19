#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd

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

    def do_ls(self, l):
        'List the available certification authorities: LS'
        list_cas(self.ca_manager)

    def do_show_ca(self, l):
        'Show certification authority information: SHOW_CA'
        raise NotImplementedError()

    def do_gen_ssh_ca(self, l):
        'Generate a SSH certification authority: GEN_SSH_CA id name'
        try:
            [ca_id, ca_name] = l.split(" ", 2)[:2]
            self.ca_manager.create_ssh_ca(ca_id, ca_name)

        except ValueError:
            print "Malformed input: %s" % l

    def do_gen_ssl_ca(self, l):
        'Generate a SSL certification authority: GEN_SSL_CA id name'

        try:
            [ca_id, ca_name] = l.split(" ", 2)[:2]
            self.ca_manager.create_ssl_ca(ca_id, ca_name)

        except ValueError:
            print "Malformed input: %s" % l

    def do_sign_request(self, l):
        'Sign a certificate from a request'

        # argument number is too low
        if len(l) < 2:

            # print available requests
            print "Available request"
            print_available_requests(self.ca_manager)

            print "=================="

            # print available ca
            print "Available authority"
            print_available_authorities(self.ca_manager)

            print "=================="

            # print usage
            print "usage: sign_request {{ n }} {{ m }}"
        else:
            [request_number, authority_number] = l.split(" ", 2)[:2]
            sign_request(self.ca_manager, request_number, authority_number)

    def do_quit(self, l):
        'Quit this shell'
        return True
