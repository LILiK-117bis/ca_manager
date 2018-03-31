#!/usr/bin/env bash
rm /var/lib/ca_manager/* -r
python3 ../../setup.py clean
cd ../../
python3 setup.py test && openssl verify -CAfile root.pem  -untrusted int.pem server.pem
