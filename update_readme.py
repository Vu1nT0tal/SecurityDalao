#!/usr/bin/python3

import json
import copy
from pathlib import Path
from datetime import datetime


def make_table(dalao: list):
    content = ''
    for idx, item in enumerate(dalao):
        content += f'| {idx+1} | [{item["name"]}]({item["url"][0]}) | {len(item["cve"])} |\n'
    return content


def get_year_dalao(dalao: dict, year: int) -> dict:
    temp_dalao = copy.deepcopy(dalao)
    for k, v in temp_dalao.items():
        new_cve = []
        for cve in v['cve']:
            if cve.startswith(f'CVE-{year}'):
                new_cve.append(cve)
        temp_dalao[k]['cve'] = new_cve
    return temp_dalao


def get_dalao_top(dalao: dict, num: int) -> list:
    dalao_list = []
    for k, v in dalao.items():
        item = {
            'name': k,
            'url': v['url'],
            'cve': v['cve']
        }
        dalao_list.append(item)

    dalao_top = sorted(dalao_list, key=lambda r: len(r['cve']), reverse=True)
    return dalao_top[:num]


def write_app():
    pass


def write_google():
    pass

def write_microsoft():
    dalao = root_path.joinpath('microsoft/data/dalao.json')
    with open(dalao, 'r') as f:
        dalao = json.load(f)
    content = '# Microsoft Top 100\n\n'
    content += '数据来源：https://msrc.microsoft.com/update-guide/acknowledgement\n\n'

    # 总榜
    dalao_top = get_dalao_top(dalao, 100)
    content += '## Top 100\n\n'
    content += '| 排名 | 姓名 | CVE数量 |\n| --- | --- | --- |\n'
    content += make_table(dalao_top)

    # 历年
    for year in range(int(datetime.now().strftime('%Y')), 2015, -1):
        content += f'\n## {year} Top 10\n\n'
        content += '| 排名 | 姓名 | CVE数量 |\n| --- | --- | --- |\n'
        year_dalao = get_year_dalao(dalao, year)
        dalao_top = get_dalao_top(year_dalao, 10)
        content += make_table(dalao_top)

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
                new_data += f'> 数据来自爬虫，每月自动更新，当前版本：{current}\n'
            else:
                new_data += line

    with open(readme, 'w+') as f:
        f.write(new_data)


if __name__ == '__main__':
    root_path = Path(__file__).parent

    write_microsoft()
    update_date()
