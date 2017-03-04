Tools
=====

There are two main tools in this module and they are the request server and the shell.

Both are used as the shell for a specific user on our secure machine.

The **request** user's shell is contained in the request_server file, the **sign** user's shell is contained in the shell file.

Request server
--------------

The request server recieves a request as a serialised JSON, if validated it will be persisted to a file, otherwise it returns a JSON serialised response.

Shell
-----
