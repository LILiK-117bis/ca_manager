..

Introduction
============

This project spurs from the need of a semi-automated way to issue certificates to our machines.

We have chosen to host this management service on a secure machine, connected to our network, and to use ssh as a mean of transport.

SSH
===

When asked with the transport mean for sign requests and get requests we decided to use ssh as it is the most secure protocol we can think of, expecially when used with public key authentication and ssh certificates.

Our tool of choice to automate much of our work is Ansible and to be able to use this management service with Ansible was a core requirement.

The request_server implements a shell for a user that Ansible can access on the secure machine, the only available command is inputing a sign request or a get request serialised as JSON.

The sign_request are then persisted to a directory with a unique identifier generated on the fly.

Authority
=========

Authorities are represented by private/public key pairs but they are also persisted as metadata to a database.

Request
========

Requests are serialised as JSON files and stored in a separate directory where they can be queried by a unique identifier

Every request gets a response with metadata about the request and the validation process.

Sign Request
------------

A sign request is JSON formatted request with metadata for the receiver and the receiver public key. The metadata required are

* content of the public key to be signed
* certificate type

The metadata returned serialise the request id into the *msg* field so that it can be shown to the user by Ansible

Get Request
-----------

A get request is JSON formatted request with the id of a certificate. As the only thing returned is the certificate there is no security issues as it is useless without the private/public key pair it refers to,

Response
========

The response to a request is JSON serialised, with these fields:

* failed
* msg
* reason
* status

Certificate
===========

A certificate is an additional file where the content is the data from a public key, hashed and signed with the authority private key.

The format is not important as it is specific to crypto utility that have to validate it so we are only storing the certificate file and persisting the associated metadata in database.

.. _user-certificate:
User Certificate
----------------

User certificates are certificate used to authenticate a user when connecting to a service; as an example we can issue a certificate to a user to connect with ssh as root to a machine without storing his pubic key on that machine.

.. _host-certificate:
Host Certificate
----------------

Host certificates are certificates issued to hosts/machines and they can be used to verify the property of a service or domain by the user.
