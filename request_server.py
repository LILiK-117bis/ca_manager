#!/usr/bin/env python3

import json
import logging
import os.path
import sys
import time
import uuid

__doc__= """
Procedure to spawn a shell for automation, used by Ansible
"""

logfile= '/home/request/request_server.log'

logging.basicConfig(
        filename= logfile,
        format= '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level= logging.INFO,
        )

logger = logging.getLogger('request_server')


REQUESTS_PATH = "/var/lib/ca_manager/requests"
RESULTS_PATH = "/var/lib/ca_manager/results"


def exit_good(response):
    logger.info('JSON accepted, send ok')
    response['failed'] = False
    response['status'] = 'ok'
    print(json.dumps(response))
    sys.exit(0)

def exit_bad(reason):
    logger.info('JSON rejected, send error; error %s', reason)
    response = {
        'failed': True,
        'status': 'error',
        'reason': reason,
        'msg': reason,
    }
    print(json.dumps(response))
    sys.exit(0)


def main():

    logger.info('Shell started')

    response = {}

    if (len(sys.argv) > 2):
        request_data = sys.argv[2]
    else:
        request_data = sys.stdin.read(10000)

    logger.info('Got request data: %s', request_data)

    try:
        metarequest = json.loads(request_data)
        assert 'type' in metarequest
    except:
        logger.info('"type" key not found in request')
        logger.info('Stopping shell')
        exit_bad('bad_json')

    if metarequest['type'] == 'sign_request':
        logger.info('Got a sign request')
        request = metarequest['request']
        request_id = str(uuid.uuid4())
        logger.info('Request id %s', request_id)

        logger.info('Writing request to target directory')
        with open(os.path.join(REQUESTS_PATH, request_id), 'w') as stream:
            stream.write(json.dumps(request))

        logger.info('Stopping shell')
        exit_good({ 'requestID': request_id })

    elif metarequest['type'] == 'get_certificate':
        logger.info('Got a GET request')
        request_id = metarequest['requestID']

        logger.info('Request id: %s', request_id)
        result_path = os.path.join(RESULTS_PATH, request_id)

        while not os.path.exists(result_path):
            time.sleep(1)

        with open(result_path, 'r') as stream:
            result_data = stream.read()

        logger.info('Stopping shell')
        exit_good({ 'requestID': request_id, 'result': result_data })

    else:
        logger.info('Request type not supported: %s', metarequest['type'])
        logger.info('Stopping shell')
        exit_bad('unknown_type')


if __name__ == '__main__':
    main()
