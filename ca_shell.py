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

    def do_quit(self, l):
        'Quit this shell'
        return True
