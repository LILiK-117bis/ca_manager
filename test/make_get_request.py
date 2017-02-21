#!/usr/bin/env python3

import argparse
import json


def main(args):
    result_dict = {}
    result_dict['type'] = 'get_certificate'
    result_dict['requestID'] = args.request_id

    print(json.dumps(result_dict))


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('request_id')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    main(parser.parse_args())
