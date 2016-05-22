#!/usr/bin/env python3

import argparse
import json


def main(args):
    result_dict = {}
    result_dict['keyType'] = 'ssh_user'
    result_dict['rootRequested'] = args.root_access
    result_dict['userName'] = args.user_name

    with open(args.pub_key_path, 'r') as stream:
        key_data = stream.read().strip()

    result_dict['keyData'] = key_data

    print(json.dumps(result_dict))


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('pub_key_path')
    parser.add_argument('user_name')
    parser.add_argument('-r', '--root-access', action='store_true')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    main(parser.parse_args())
