import re
import json
import string
import requests
from lxml import etree
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import sys
sys.path.append('..')
from utils import Color, Readme

import spacy
nlp = spacy.load('en_core_web_md')


class Intel:
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

    @staticmethod
    def downloadThread(url: str):
        Color.print_focus(url)
        r = requests.get(url)
        soup = BeautifulSoup(r.content, 'html.parser')

        found_cve = soup.find_all(string=re.compile('^CVE*'))   # CVEID:, CVE-
        cve = []
        for i in found_cve:
            if text := re.findall('CVE-\d+.-\d+.', i.get_text()):
                cve.append(text[0])

        try:
            dalao = []
            found_dalao = soup.find(string=re.compile('^Acknowledgements*')).find_previous().find_next_siblings('p')
            print(found_dalao)
            for line in found_dalao:
                dalao_text = line.get_text()
                doc = nlp(dalao_text)
                dalao.extend([i.text for i in doc.ents if i.label_ == 'PERSON'])
                if not dalao and 'thank' in dalao_text and 'for' in dalao_text:     # 尝试补救一下
                    name = dalao_text.split('thank')[1].split('for')[0].split('(')[0].strip()
                    dalao.append(name)
        except Exception as e:
            print(e)

        print(cve, dalao)
        if cve and dalao:
            return dict({'url': url}, **{name.rsplit(string.digits)[0]: cve for name in dalao})
        else:
            Color.print_failed(url)

    def download(self):
        base_url = 'https://www.intel.com'
        advisories_url = f'{base_url}/content/www/us/en/security-center/default.html'
        r = requests.get(advisories_url)
        root = etree.HTML(r.content)
        table = root.xpath('//*[@id="editorialTableBlade-1"]/div/div[2]/div/table/tbody/tr')
        urls = []
        for i in table:
            href = i.xpath('td/a/@href')[0]
            urls.append(f'{base_url}{href}')

        with ThreadPoolExecutor(1) as executor:
            tasks = [executor.submit(Intel.downloadThread, url) for url in urls]
            result = [task.result() for task in as_completed(tasks) if task.result()]

        with open(self.raw_path, 'w+') as f:
            f.write(json.dumps(result, indent=4))
            Color.print_success(f'[+] download: {self.raw_path}')
        return result

    def get_dalao(self):
        dalao = defaultdict(lambda: defaultdict(list))
        for item in self.data:
            for name, value in item.items():
                if name != 'url':
                    dalao[name]['url'] = self.namelist.get(name)
                    dalao[name]['cve'].extend(value)

        with open(self.dalao_path, 'w+') as f:
            f.write(json.dumps(dalao, indent=4))
            Color.print_success(f'[+] dalao: {self.dalao_path}')
        return dalao

    def update_readme(self, dalao=None):
        if not dalao:
            with open(self.dalao_path, 'r') as f:
                dalao = json.load(f)

        content = '# Intel Top 100\n\n'
        content += '数据来源：https://www.intel.com/content/www/us/en/security-center/default.html\n\n'

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
