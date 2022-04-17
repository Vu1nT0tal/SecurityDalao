import json
import requests
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
from collections import defaultdict

import sys

from requests import request
sys.path.append('..')
from utils import Color, Readme

import spacy
nlp = spacy.load('en_core_web_md')

class Nvidia:
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
        results = []

        r = requests.get('https://www.nvidia.com/en-us/security/acknowledgements')
        soup = BeautifulSoup(r.content, 'html.parser')
        found = soup.find_all('li', class_='accordion item')
        for item in found:
            year = item.find('h4').get_text()
            trs = item.find_all('tr')[1:]
            result = {'year': year}
            for tr in trs:
                tds = tr.find_all('td')
                if len(tds) > 1:
                    cve_text = tds[1].get_text().replace('\u2011', '\u002d').strip()    # https://www.fileformat.info/info/unicode/char/002d/index.htm
                    if ',' in cve_text:
                        cve = [i.strip() for i in cve_text.split(',') if i.strip().startswith('CVE')]
                    elif ' ' in cve_text:
                        cve = [i for i in cve_text.split() if i.startswith('CVE')]
                    else:
                        cve = [cve_text]
                    name = tds[0].get_text()
                    doc = nlp(name)
                    dalao = [i.text for i in doc.ents if i.label_ == 'PERSON']
                    if not dalao and ('of' in name or ',' in name):     # 尝试补救一下
                        dalao = [name.split('of')[0].split(',')[0].strip()]
                    if cve and dalao:
                        result.update({name: cve for name in dalao})
            results.append(result)

        with open(self.raw_path, 'w+') as f:
            f.write(json.dumps(results, indent=4, ensure_ascii=False))
            Color.print_success(f'[+] download: {self.raw_path}')
        return results

    def get_dalao(self):
        dalao = defaultdict(lambda: defaultdict(list))
        for item in self.data:
            for name, value in item.items():
                if name != 'year':
                    dalao[name]['url'].extend([])
                    dalao[name]['cve'].extend(value)
        
        with open(self.dalao_path, 'w+') as f:
            f.write(json.dumps(dalao, indent=4, ensure_ascii=False))
            Color.print_success(f'[+] dalao: {self.dalao_path}')
        return dalao

    def update_readme(self, dalao=None):
        if not dalao:
            with open(self.dalao_path, 'r') as f:
                dalao = json.load(f)

        content = '# Nvidia Top 100\n\n'
        content += '数据来源：https://www.nvidia.com/en-us/security/acknowledgements\n\n'

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
