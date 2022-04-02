#!/usr/bin/python3

import json
from pathlib import Path
from datetime import datetime


def write_app():
    pass


def write_google():
    pass

def write_microsoft():
    dalao = root_path.joinpath('microsoft/data/dalao_top.json')
    with open(dalao, 'r') as f:
        dalao = json.load(f)

    content = '# Microsoft Top 100\n\n'
    content += '| 排名 | 姓名 | CVE数量 |\n| --- | --- | --- |\n'
    for idx, item in enumerate(dalao):
        content += f'| {idx+1} | [{item["name"]}]({item["url"][0]}) | {len(item["cve"])} |\n'

    readme = root_path.joinpath('microsoft/README.md')
    with open(readme, 'w+') as f:
        f.write(content)


def update_date():
    readme = root_path.joinpath('README.md')
    with open(readme, 'r') as f:
        new_data = ''
        for line in f.readlines():
            if '当前版本' in line:
                current = datetime.now().strftime('%Y-%m-%d')
                new_data += f'> 每月自动更新，当前版本：{current}\n'
            else:
                new_data += line

    with open(readme, 'w+') as f:
        f.write(new_data)


if __name__ == '__main__':
    root_path = Path(__file__).absolute().parents[1]

    write_microsoft()
    update_date()
