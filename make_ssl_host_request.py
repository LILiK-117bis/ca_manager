#!/usr/bin/env python3

import argparse
import json


def main(args):
    result_dict = {}
    result_dict['keyType'] = 'ssl_host'
    result_dict['hostName'] = args.host_name

    with open(args.pub_key_path, 'r') as stream:
        key_data = stream.read().strip()

    result_dict['keyData'] = key_data

    request = { 'type': 'sign_request', 'request': result_dict }

    print(json.dumps(request))


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('pub_key_path')
    parser.add_argument('host_name')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    main(parser.parse_args())
