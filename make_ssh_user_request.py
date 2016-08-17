#!/usr/bin/env python3

import argparse
import json
from os import path

def main(args):
    result_dict = {}
    result_dict['keyType'] = 'ssh_user'
    result_dict['rootRequested'] = args.root_access
    result_dict['userName'] = args.user_name

    if path.exists(args.pub_key_path):
        with open(args.pub_key_path, 'r') as stream:
            key_data = stream.read().strip()
    else:
        key_data = args.pub_key_path

    result_dict['keyData'] = key_data

    request = { 'type': 'sign_request', 'request': result_dict }

    print(json.dumps(request))


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('pub_key_path')
    parser.add_argument('user_name')
    parser.add_argument('-r', '--root-access', action='store_true')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    main(parser.parse_args())
