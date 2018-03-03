#!/usr/bin/env python3

import argparse
import json


def main(args):
    result_dict = {}
    result_dict['keyType'] = 'ssl_user'
    result_dict['userName'] = args.user_name

    with open(args.certificate_signin_request_path, 'r') as stream:
        key_data = stream.read().strip()
        result_dict['keyData'] = key_data
        request = {'type': 'sign_request', 'request': result_dict}
        print(json.dumps(request))


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('certificate_signin_request_path')
    parser.add_argument('user_name')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    main(parser.parse_args())
