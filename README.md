CA manager
==========

This collection of tools is our take on managing a CA, signing SSH keys and certificates, signin SSL certificates.

### Tools

#### `request_server.py`

This is a shell for a user, the shell only reads the input from the user and return a json.

The input must be a JSON file, e.g

```JSON
{
	{
		"keyType": "ssh_host",
		"hostName": "my_new_server",
		"keyData": "ssh-ed25519 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa root@my_new_server"
	},
	"type": "sign_request"
}
```

the example is a `sign_request` for a ssh host certificate

The server logs can be found at `/home/request/request_server.log`

#### `ca_sheel.py`

This is a shell for a user, the shell limits the commands to the one we are interested, like generating a SSH/SSL CA, signing keys.

### Configuration

The only configuration needed is the path where to operate, modifying te file `paths.py` is all is needed.
