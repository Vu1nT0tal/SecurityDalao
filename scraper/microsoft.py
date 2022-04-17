import sys
import json
import requests
from lxml import etree
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.append('..')
from utils import Color, Readme


class Microsoft:
    def __init__(self, local_path: Path, download: bool=False) -> None:
        self.local_path = local_path
        self.raw_path = local_path.joinpath('data/raw_data.json')
        self.dalao_path = local_path.joinpath('data/dalao.json')
        if download:
            self.data = self.download()
        else:
            with open(self.raw_path, 'r') as f:
                self.data = json.load(f)

    def download(self):
        start_date = '2016-01-01'
        end_date = datetime.now().strftime('%Y-%m-%d')

        result = []
        for skip in range(0, 100000, 500):
            url = f'https://api.msrc.microsoft.com/sug/v2.0/en-US/acknowledgement?$orderby=releaseDate desc&$filter=(releaseDate gt {start_date}T00%3A00%3A00%2B08%3A00) and (releaseDate lt {end_date}T23%3A59%3A59%2B08%3A00)&$skip={skip}'
            if value := requests.get(url).json()['value']:
                result += value
            else:
                break

        with open(self.raw_path, 'w+') as f:
            f.write(json.dumps(result, indent=4))
            Color.print_success(f'[+] download: {self.raw_path}')
        return result

    def get_dalao(self):
        def get_names(name):
            names = []
            if ',' in name or 'and' in name or '&' in name:
                names = name.replace('and', ',').replace('&', ',').split(',')
                names = [i for i in names if i.strip() != '']
            else:
                names.append(name)
            return names

        def insert_item(name, cve, url=''):
            for i in ['(', '@']:
                if i in name:
                    name = name.split(i)[0]
            name = name.strip()

            if dalao.get(name):
                dalao[name]['cve'].append(cve)
                if url and url not in dalao[name]['url']:
                    dalao[name]['url'].append(url)
            else:
                dalao[name]['url'] = [url] if url else []
                dalao[name]['cve'] = [cve]

        type_data = []
        for item in self.data:
            if item.get('cveNumber') and item['cveNumber'].startswith('CVE'):
                type_data.append(item)

        global dalao
        dalao = defaultdict(dict)
        for item in type_data:
            cve = item['cveNumber']
            acktext = item.get('ackText')
            if not acktext:
                continue
            for i in [' working with ', ' from ', ' of ', ' with ', ' in ']:
                if i.casefold() in acktext:
                    acktext = acktext.split(i.casefold())[0].strip()

            Color.print_focus(f'{cve} {acktext}')
            if acktext.startswith('<a'):
                root = etree.HTML(acktext)
                try:
                    for a in root.xpath('//a'):
                        url = a.xpath('@href')[0].strip()
                        name = a.xpath('text()')[0]
                        for name in get_names(name):
                            insert_item(name, cve, url)
                            Color.print_success(f'{name} {url}')
                except Exception as e:
                    Color.print_failed(f'{cve} {acktext}')
                    print(e)
            elif 'href' in acktext:
                acktext = acktext.split('<a')[0]
                for name in get_names(acktext):
                    insert_item(name, cve)
                    Color.print_success(f'{name}')
            else:
                for name in get_names(acktext):
                    insert_item(name, cve)
                    Color.print_success(f'{name}')

        with open(self.dalao_path, 'w+') as f:
            f.write(json.dumps(dalao, indent=4))
            Color.print_success(f'[+] dalao: {self.dalao_path}')
        return dalao

    def update_readme(self, dalao=None):
        if not dalao:
            with open(self.dalao_path, 'r') as f:
                dalao = json.load(f)

        content = '# Microsoft Top 100\n\n'
        content += '数据来源：https://msrc.microsoft.com/update-guide/acknowledgement\n\n'

        # 总榜
        dalao_top = Readme.get_dalao_top(dalao, 100)
        content += '## Top 100\n\n'
        content += '| 排名 | 姓名 | CVE数量 |\n| --- | --- | --- |\n'
        content += Readme.make_table(dalao_top)

        # 历年
        first_year = Readme.get_first_year(dalao)
        for year in range(int(datetime.now().strftime('%Y')), first_year-1, -1):
            content += f'\n## {year} Top 10\n\n'
            content += '| 排名 | 姓名 | CVE数量 |\n| --- | --- | --- |\n'
            year_dalao = Readme.get_year_dalao(dalao, year)
            dalao_top = Readme.get_dalao_top(year_dalao, 10)
            content += Readme.make_table(dalao_top)

        readme = self.local_path.joinpath('README.md')
        with open(readme, 'w+') as f:
            f.write(content)
            Color.print_success(f'[+] update readme: {readme}')
