#!/usr/bin/env bash
rm /var/lib/ca_manager/* -r
python3 ../../setup.py clean
/usr/bin/expect -f test.exp && openssl verify -CAfile ../../root.pem  -untrusted ../../int.pem ../../server.pem
