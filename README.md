CA manager
==========

![My authority]()

This collection of tools is our take on managing a CA, signing SSH keys and certificates, signin SSL certificates.

### Tools

#### `request_server.py`

This is a shell for a user, the shell only reads the input from the user and return a JSON, this user can be used with Ansible to request and retrive certificates.

The server logs can be found at `/home/request/request_server.log`

#### `ca_sheel.py`

This is a shell for a user, the shell limits the commands to the one we are interested, like generating a SSH/SSL CA, signing keys.

### Configuration

The only configuration needed is the path where to operate, modifying te file `paths.py` is all is needed.
