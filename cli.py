#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ca_shell import CAManagerShell
from ca_manager import CAManager, init_manager
from paths import *

if __name__ == '__main__':

    init_manager([
        MANAGER_PATH,
        REQUESTS_PATH,
        OUTPUT_PATH,
        RESULTS_PATH,
        ])


    with CAManager(MANAGER_PATH) as ca_manager:

        CAManagerShell(ca_manager).cmdloop()
