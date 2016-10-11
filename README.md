CA manager
==========

This collection of tools is our take on managing a CA, signing SSH keys and certificates, signin SSL certificates.

### Tools

#### `request_server.py`

This is a shell for a user, the shell only reads the input from the user and return a JSON, this user can be used with Ansible to request and retrive certificates.

The server logs can be found at `/home/request/request_server.log`

##### sign_request

The input must be a JSON file, e.g

```JSON
{
	"request": {
		"keyType": "ssh_host",
		"hostName": "my_new_server",
		"keyData": "ssh-ed25519 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa root@my_new_server"
	},
	"type": "sign_request"
}
```

the example is a `sign_request` for a ssh host certificate.

The shell just output a json with `status`, `reason`, `failed` and `msg` keys.

```JSON
{
	"failed" : ...,
	"msg" : ...,
	"reason" : ...,
	"status" : ...
}
```

The keys `failed` and `msg` are only requested to comply with ansible.

#### `ca_sheel.py`

This is a shell for a user, the shell limits the commands to the one we are interested, like generating a SSH/SSL CA, signing keys.

```
# LILiK CA Manager

Welcome to the certification authority shell.
Type help or ? to list commands.
	    
(CA Manager)> ?

Documented commands (type help <topic>):
========================================
describe_cas  gen_ca  help  ls_ca  ls_requests  quit  sign_request
```

### Configuration

The only configuration needed is the path where to operate, modifying te file `paths.py` is all is needed.
