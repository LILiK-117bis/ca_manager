CA manager
==========

![it's true]

This collection of tools is our take on managing a CA, signing SSH keys and certificates, signin SSL certificates.

### Install

Install from pip with the latest release

### Scripts

With the library are distributed the following scripts

#### ca-server

This is a shell for a user, the shell only reads the input from the user and return a JSON, this user can be used with Ansible to request and retrieve certificates.

The server logs can be found at `/home/request/request_server.log`

A playbook example can be found in `ansible.yaml`

#### ca-shell

This is a shell for a user, the shell limits the commands to the one we are interested, like generating a SSH/SSL CA, signing keys.

[it's true]: https://user-images.githubusercontent.com/4076473/27771545-82c82628-5f50-11e7-91f2-86840a57dc07.jpg "For some definition of law"

