from unittest import TestCase

from ca_manager.models.ssl import SSLAuthority
from datetime import datetime
from ca_manager.manager import CAManager, init_manager
from ca_manager.paths import *
from ca_manager.shell import CAManagerShell
import ca_manager.shell
import ca_manager.server
import json
from shutil import copyfile

class TestChain(TestCase):
    def test_chain(self):
        password = 'root'

        init_manager([
            MANAGER_PATH,
            REQUESTS_PATH,
            OUTPUT_PATH,
            RESULTS_PATH,
            ])


        my_ca_manager = CAManager(MANAGER_PATH)

        root_ca = SSLAuthority(
                ca_id="root",
                name="root",
                serial=0,
                active=True,
                creation_date=datetime.now(),
                )

        root_ca.generate(isRoot=True, password=password)
        root_ca.save()

        int_ca = SSLAuthority(
                ca_id="int",
                name="int",
                serial=0,
                active=True,
                creation_date=datetime.now(),
                )

        request = int_ca.generate(isRoot=False, password=password)

        int_ca.save()
        response = ca_manager.server.handle_request(request_data = json.dumps(request))

        root_ca.sign(my_ca_manager.request[response['requestID']], password=password)

        *_, certificate = my_ca_manager.certificate

        copyfile(certificate.path, '%s.pub' %my_ca_manager.ca['int'].path)

        response = ca_manager.server.handle_request(request_data = '{"type": "sign_request", "request": {"hostName": "dovecot.lilik.it", "keyType": "ssl_host", "keyData": "-----BEGIN CERTIFICATE REQUEST-----\\nMIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\\nITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN\\nAQEBBQADggEPADCCAQoCggEBALbQkfSBjQN3J7tsVwDYEnnl+9vMSNyesExq4jzd\\n5JlaUcUXEt1iKZK9jGQtgUTRerUtHAhurB1NCWN76pD1IUQZq5fT8UtuMRJYOiC1\\njCd0jI9rR7xIR/QPWOUj6Tett8zt6Ij3/BJ6yunbjcjuVhP0gHeS33NmWbzoS7jm\\nz/ycaX29j6W+ckpDn2OA9sv9/vrtIM4KoBq7fWRj/hzh9CwPunlLYUF+80R4ExeC\\nS5XBQUpCzOQ6Db681Cbcy4ecXMufB2PXx51OZCsNATyVPujKP4Yo2hysrFm95bK3\\n4F2mrHIA2/V/Ib/Q3ler3+AO6YpoOYR8VDVzMcSStCTvEQ0CAwEAAaAAMA0GCSqG\\nSIb3DQEBCwUAA4IBAQCvFdwQ9LVL3adMAt0m01d4MBhI2r3h+wdEq47FF/O3e8FV\\nClxVbRagT7HDjVsZylvLOcykrnT5i8TQ/PPTkFFd2iAxi9W3yAwIaCfmoCG/UR3D\\ng/nVstqHZNPTgsWwUUtfq2NT+Z96GxZ+JJ9ni7yf/9hgWLIXasYc5uG8XHFcjWeD\\n4aWa1q5owt8iNkF9bMo7EvXA8Nc0EGyAV3ElwJq9qX4a7nMRN12hldlyXydaLgtt\\n64b3rKaarDKroVwi5Gibu0ZgsCC0mN1V81aLt00YcC9GW+GaA71xdCe8s13yZoVX\\n/41EfC61JWnjEVCrVgxlFa+Aoo4nFz34ePLY5Tfe\\n-----END CERTIFICATE REQUEST-----"}}')

        int_ca.sign(my_ca_manager.request[response['requestID']], password=password)

        *_, certificate = my_ca_manager.certificate

        copyfile('%s.pub' %my_ca_manager.ca['root'].path, 'root.pem')
        copyfile('%s.pub' %my_ca_manager.ca['int'].path, 'int.pem')
        copyfile(certificate.path, 'server.pem')

        certificate.revoke()

        int_ca.generate_crl(password)
        root_ca.generate_crl(password)

        copyfile("%s.crl"%my_ca_manager.ca['root'].path, 'root.crl')
        copyfile("%s.crl"%my_ca_manager.ca['int'].path, 'int.crl')
