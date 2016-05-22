#!/usr/bin/env python3

import os.path
import sys
import time
import uuid


REQUESTS_PATH = "/var/lib/ca_manager/requests"
RESULTS_PATH = "/var/lib/ca_manager/results"


def exit_good(response):
    response['status'] = 'ok'
    print(json.dumps(response))
    sys.exit(0)


def exit_bad(reason):
    response['status'] = 'error'
    response['reason'] = reason
    print(json.dumps(response))
    sys.exit(0)


def main():
    global REQUESTS_PATH
    global RESULTS_PATH

    response = {}

    try:
        request_data = sys.stdin.read(10000)
        metarequest = json.loads(request_data)
        assert 'type' in metarequest
    except:
        exit_bad('bad_json')

    if metarequest['type'] == 'sign_request':
        request = metarequest['request']
        request_id = str(uuid.uuid4())

        with open(os.path.join(REQUESTS_PATH, request_id), 'w') as stream:
            stream.write(json.dumps(request))

        exit_good({ 'requestID': request_id })
    elif metarequest['type'] == 'get_certificate':
        request_id = metarequest['requestID']

        result_path = os.path.join(RESULTS_PATH, request_id)

        while not os.path.exists(result_path):
            time.sleep(1)

        with open(result_path, 'r') as stream:
            result_data = stream.read()

        exit_good({ 'requestID': request_id, 'requestData': request_data })
    else:
        exit_bad('unknown_type')


if __name__ == '__main__':
    main()
