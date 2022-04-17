import sys
import json
import requests
from lxml import etree
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.append('..')
from utils import Color, Readme

import spacy
nlp = spacy.load('en_core_web_md')


class Microsoft:
    def __init__(self, local_path: Path, download: bool=False) -> None:
        self.local_path = local_path
        self.raw_path = local_path.joinpath('data/raw_data.json')
        self.dalao_path = local_path.joinpath('data/dalao.json')

        with open(local_path.parent.joinpath('namelist.json'), 'r') as f:
            self.namelist = json.load(f)

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
        type_data = [item for item in self.data if item.get('cveNumber') and item['cveNumber'].startswith('CVE')]

        result = {}
        for item in type_data:
            cve = item['cveNumber']
            acktext = item.get('ackText')
            if not acktext:
                continue

            dalao_text = str(etree.HTML(acktext).xpath('string(.)'))
            doc = nlp(dalao_text)
            dalao = [i.text for i in doc.ents if i.label_ == 'PERSON']
            if not dalao:   # 尝试补救一下
                dalao = [dalao_text.strip()]
                for i in ['working with', ' from ', ' of ', ' with ', ' in ']:
                    if i.casefold() in dalao_text:
                        dalao = [dalao_text.split(i.casefold())[0].split('(')[0].split('@')[0].strip()]

            # print(dalao_text, cve)
            # print(dalao)
            if cve and dalao:
                for name in dalao:
                    if result.get(name):
                        result[name]['cve'].append(cve)
                    else:
                        result[name] = {
                            'url': self.namelist.get(name),
                            'cve': [cve]
                        }

        with open(self.dalao_path, 'w+') as f:
            f.write(json.dumps(result, indent=4))
            Color.print_success(f'[+] dalao: {self.dalao_path}')
        return result

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
