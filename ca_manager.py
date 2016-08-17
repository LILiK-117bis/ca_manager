#!/usr/bin/env python3

import hashlib
import json
import os
import os.path
import shutil
import sqlite3
import subprocess
import tempfile


MANAGER_PATH = "/var/lib/ca_manager/private"
REQUESTS_PATH = "/var/lib/ca_manager/requests"
OUTPUT_PATH = "/var/lib/ca_manager/outputs"
RESULTS_PATH = "/var/lib/ca_manager/results"


class SignRequest(object):
    def __init__(self, req_id):
        self.req_id = req_id

    def get_name(self):
        raise NotImplementedError()

    def get_fields(self):
        raise NotImplementedError()


class UserSSHRequest(SignRequest):
    def __init__(self, req_id, user_name, root_requested, key_data):
        super().__init__(req_id)

        self.user_name = user_name
        self.root_requested = root_requested
        self.key_data = key_data

    def get_name(self):
        return "User: %s [R:%d]" % (self.user_name, int(self.root_requested))

    def get_fields(self):
        return [
            ("User name", self.user_name),
            ("Root access requested", 'yes' if self.root_requested else 'no')
        ]

class HostSSLRequest(SignRequest):
    def __init__(self, req_id, host_name, key_data):
        super().__init__(req_id)

        self.host_name = host_name
        self.key_data = key_data

    def get_name(self):
        return "Hostname: %s" % self.host_name

    def get_fields(self):
        return [
            ("Hostname", self.host_name)
        ]

class HostSSHRequest(SignRequest):
    def __init__(self, req_id, host_name, key_data):
        super().__init__(req_id)

        self.host_name = host_name
        self.key_data = key_data

    def get_name(self):
        return "Hostname: %s" % self.host_name

    def get_fields(self):
        return [
            ("Hostname", self.host_name)
        ]


class Authority(object):
    ca_type = None

    def __init__(self, ca_id, name, path):
        self.ca_id = ca_id
        self.name = name
        self.path = path

    def generate(self):
        raise NotImplementedError()

    def sign(self, request):
        raise NotImplementedError()


class SSHAuthority(Authority):
    ca_type = 'ssh'

    key_algorithm = 'ed25519'

    user_validity = '+52w'
    host_validity = '+52w'

    def generate(self):
        if os.path.exists(self.path):
            raise ValueError("A CA with the same id and type already exists")

        subprocess.call(['ssh-keygen',
            '-f', self.path,
            '-t', self.key_algorithm,
            '-C', self.name])

        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(0))


    def sign(self, request):
        global OUTPUT_PATH

        assert type(request) in [UserSSHRequest, HostSSHRequest]

        pub_key_path = os.path.join(OUTPUT_PATH, request.req_id + '.pub')
        cert_path = os.path.join(OUTPUT_PATH, request.req_id + '-cert.pub')

        with open(self.path + '.serial', 'r') as stream:
            next_serial = int(stream.read())
        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(next_serial + 1))

        with open(pub_key_path, 'w') as stream:
            stream.write(request.key_data)

        ca_private_key = self.path

        if type(request) == UserSSHRequest:
            login_names = [request.user_name]
            if request.root_requested:
                login_names.append('root')

            subprocess.call(['ssh-keygen',
                '-s', ca_private_key,
                '-I', 'user_%s' % request.user_name,
                '-n', ','.join(login_names),
                '-V', self.user_validity,
                '-z', str(next_serial),
                pub_key_path])
        elif type(request) == HostSSHRequest:
            subprocess.call(['ssh-keygen',
                '-s', ca_private_key,
                '-I', 'host_%s' % request.host_name.replace('.', '_'),
                '-h',
                '-n', request.host_name,
                '-V', self.host_validity,
                '-z', str(next_serial),
                pub_key_path])

        return cert_path

class SSLAuthority(Authority):
    ca_type = 'ssl'

    ca_key_algorithm = 'des3'
    key_length = '4096'

    key_algorithm = 'sha256'
    ca_validity = '365'
    cert_validity = '365'

    def generate(self):
        if os.path.exists(self.path):
            raise ValueError("A CA with the same id and type already exists")

        subprocess.call(['openssl',
            'genrsa',
            '-%s'%self.ca_key_algorithm,
            '-out', '%s'%(self.path),
            self.key_length])

        subprocess.call(['openssl',
            'req',
            '-new',
            '-x509',
            '-days', self.ca_validity,
            '-key', self.path,
            # '-extensions', 'v3_ca'
            '-out', "%s.pub"%self.path,
            # '-config', "%s.conf"%self.path
            ])

        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(0))


    def sign(self, request):
        global OUTPUT_PATH

        assert type(request) in [HostSSLRequest]

        pub_key_path = os.path.join(OUTPUT_PATH, request.req_id + '.pub')
        cert_path = os.path.join(OUTPUT_PATH, request.req_id + '-cert.pub')

        with open(self.path + '.serial', 'r') as stream:
            next_serial = int(stream.read())
        with open(self.path + '.serial', 'w') as stream:
            stream.write(str(next_serial + 1))

        with open(pub_key_path, 'w') as stream:
            stream.write(request.key_data)

        ca_private_key = self.path

        # openssl x509 -req -days 360 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt        # print()
        subprocess.check_output(['openssl',
                        'x509',
                        '-req',
                        '-days', self.ca_validity,
                        '-in', pub_key_path,
                        '-CA', "%s.pub"%self.path,
                        '-CAkey', self.path,
                        '-CAcreateserial',
                        '-out', cert_path,
                        '-%s'%self.key_algorithm])

        return cert_path

class CAManager(object):
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.conn = sqlite3.connect(self._get_db_path())

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            print(exc_type, exc_value)
            print(traceback)

        self.conn.close()

    def _get_db_path(self):
        return os.path.join(self.path, 'ca_manager.db')

    def _get_ssh_cas_dir(self):
        return os.path.join(self.path, 'ssh_cas')

    def _get_ssh_ca_path(self, ca_id):
        cas_dir = self._get_ssh_cas_dir()
        return os.path.join(cas_dir, ca_id)

    def _get_ssl_cas_dir(self):
        return os.path.join(self.path, 'ssl_cas')

    def _get_ssl_ca_path(self, ca_id):
        cas_dir = self._get_ssl_cas_dir()
        return os.path.join(cas_dir, ca_id)

    def create_ssh_ca(self, ca_id, ca_name):
        ca_path = self._get_ssh_ca_path(ca_id)

        authority = SSHAuthority(ca_id, ca_name, ca_path)

        authority.generate()

        c = self.conn.cursor()
        c.execute("""INSERT INTO cas VALUES (?, ?, 'ssh')""",
                (ca_id, ca_name))
        self.conn.commit()

    def create_ssl_ca(self, ca_id, ca_name):
        ca_path = self._get_ssl_ca_path(ca_id)

        authority = SSLAuthority(ca_id, ca_name, ca_path)

        authority.generate()

        c = self.conn.cursor()
        c.execute("""INSERT INTO cas VALUES (?, ?, 'ssl')""",
                (ca_id, ca_name))
        self.conn.commit()

    def get_cas_list(self):
        c = self.conn.cursor()

        c.execute("""SELECT id, name, type FROM cas""")

        return c.fetchall()

    def get_ca(self, ca_id):
        c = self.conn.cursor()
        c.execute("""SELECT name, type FROM cas WHERE id = ?""", (ca_id, ))

        ca_name, ca_type = c.fetchone()

        if ca_type == 'ssh':
            ca_path = self._get_ssh_ca_path(ca_id)
            return SSHAuthority(ca_id, ca_name, ca_path)
        elif ca_type == 'ssl':
            ca_path = self._get_ssl_ca_path(ca_id)
            return SSLAuthority(ca_id, ca_name, ca_path)

    def get_requests(self):
        global REQUESTS_PATH

        req_objs = []

        for request_name in os.listdir(REQUESTS_PATH):
            request_path = os.path.join(REQUESTS_PATH, request_name)

            with open(request_path, 'r') as stream:
                req = json.load(stream)

            if req['keyType'] == 'ssh_user':
                user_name = req['userName']
                root_requested = req['rootRequested']
                key_data = req['keyData']

                req_objs.append(
                        UserSSHRequest(
                            request_name, user_name, root_requested, key_data))
            elif req['keyType'] == 'ssh_host':
                host_name = req['hostName']
                key_data = req['keyData']

                req_objs.append(
                        HostSSHRequest(
                            request_name, host_name, key_data))
            elif req['keyType'] == 'ssl_host':
                host_name = req['hostName']
                key_data = req['keyData']

                req_objs.append(
                        HostSSLRequest(
                            request_name, host_name, key_data))

        return req_objs

    def drop_request(self, request):
        global REQUESTS_PATH

        os.unlink(os.path.join(REQUESTS_PATH, request.req_id))


def init_manager(paths):
    db_path = os.path.join(paths[0], 'ca_manager.db')

    directories = ['ssh_cas', 'ssl_cas']

    for dirpath in paths:
        if not os.path.exists(dirpath):
            os.mkdir(dirpath)

    for dirname in directories:
        dirpath = os.path.join(paths[0], dirname)

        if not os.path.exists(dirpath):
            os.mkdir(dirpath)

    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE cas (id text, name text, type text)""")
        conn.commit()
        conn.close()


def main():
    global MANAGER_PATH

    init_manager([MANAGER_PATH, REQUESTS_PATH, OUTPUT_PATH, RESULTS_PATH])

    menu_entries = [
        ("list-cas", "List available CAs"),
        ("show-ca", "Show CA info"),
        ("gen-ssh-ca", "Generate SSH CA"),
        ("gen-ssl-ca", "Generate SSL CA"),
        ("sign-request", "Sign request"),
        ("help", "Show this message"),
        ("quit", "Quit from CA manager")
    ]

    with CAManager(MANAGER_PATH) as ca_manager:
        print("# LILiK CA Manager")

        exiting = False

        while not exiting:
            selection = input('Command> ')

            if selection == 'help':
                print("Available commands:")
                for entry_id, entry_name in menu_entries:
                    print("%-13s :    %s" % (entry_id, entry_name))
            elif selection == 'quit':
                exiting = True
            elif selection == 'list-cas':
                list_cas(ca_manager)
            elif selection == 'show-ca':
                pass
            elif selection == 'gen-ssh-ca':
                ca_id = input("CA unique id> ")
                ca_name = input("CA human-readable name> ")
                ca_manager.create_ssh_ca(ca_id, ca_name)
            elif selection == 'gen-ssl-ca':
                ca_id = input("CA unique id> ")
                ca_name = input("CA human-readable name> ")
                ca_manager.create_ssl_ca(ca_id, ca_name)
            elif selection == 'sign-request':
                sign_request(ca_manager)
            else:
                print("Unrecognized command. Type 'help' to show available "
                        "commands.")


def list_cas(ca_manager):
    for ca_id, ca_name, ca_type in ca_manager.get_cas_list():
        print("- [%3s] %-15s (%s)" % (ca_type, ca_id, ca_name))


def sign_request(ca_manager):
    global RESULTS_PATH

    list_cas(ca_manager)
    ca_selection = input('Select a CA> ')

    try:
        authority = ca_manager.get_ca(ca_selection)
    except:
        print("Could not find CA '%s'" % ca_selection)
        return

    requests = ca_manager.get_requests()
    for i, request in enumerate(requests):
        print("%2d) %s - %s" % (i, request.req_id, request.get_name()))
    req_selection = input('Select a request> ')

    try:
        req_selection = int(req_selection)
        req_obj = requests[req_selection]
    except:
        return

    print("Request details:")
    for field_name, field_value in req_obj.get_fields():
        print("- %s: %s" % (field_name, field_value))

    h = hashlib.sha256()
    h.update(req_obj.key_data.encode('utf-8'))
    print("Request hash: %s" % h.hexdigest())

    print("You are about to sign this request with the following CA:")
    print("- %s (%s)" % (authority.ca_id, authority.name))
    confirm = input('Proceed? (type yes)> ')
    if confirm != 'yes':
        return

    cert_path = authority.sign(request)
    ca_manager.drop_request(request)

    shutil.copy(cert_path, os.path.join(RESULTS_PATH, request.req_id))


if __name__ == '__main__':
    main()
