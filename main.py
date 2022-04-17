#!/usr/bin/python3

import argparse
from pathlib import Path
from datetime import datetime

from scraper import *


def update_date():
    readme = root_path.joinpath('README.md')
    with open(readme, 'r') as f:
        new_data = ''
        for line in f.readlines():
            if '当前版本' in line:
                current = datetime.now().strftime('%Y-%m-%d')
                new_data += f'> 数据来自爬虫，每月自动更新，当前版本：{current}\n'
            else:
                new_data += line

    with open(readme, 'w+') as f:
        f.write(new_data)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--readme', help='also update readme', action='store_true',required=False)
    return parser.parse_args()


if __name__ == '__main__':
    args = argument()

    root_path = Path(__file__).absolute().parent
    data_path = root_path.joinpath('data')

    plugin = {
        'apple': False,
        'google': False,
        'intel': False,
        'microsoft': False,
        'nvidia': False,
        'oracle': False,
        'qualcomm': True
    }

    if plugin['apple']:
        pass    # TODO

    if plugin['google']:
        pass    # TODO

    if plugin['intel']:
        intel = Intel(data_path.joinpath('intel'), download=True)
        data = intel.get_dalao()

        if args.readme:
            intel.update_readme(data)

    if plugin['microsoft']:
        microsoft = Microsoft(data_path.joinpath('microsoft'), download=True)
        data = microsoft.get_dalao()

        if args.readme:
            microsoft.update_readme(data)

    if plugin['nvidia']:
        nvidia = Nvidia(data_path.joinpath('nvidia'), download=True)
        data = nvidia.get_dalao()

        if args.readme:
            nvidia.update_readme(data)

    if plugin['oracle']:
        pass    # TODO

    if plugin['qualcomm']:
        qualcomm = Qualcomm(data_path.joinpath('qualcomm'), download=True)
        data = qualcomm.get_dalao()

        if args.readme:
            qualcomm.update_readme(data)

    update_date()
