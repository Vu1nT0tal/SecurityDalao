import re
import json
import string
import requests
from lxml import etree
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
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
            text = re.findall('CVE-\d+.-\d+.', i.get_text())
            if text:
                cve.append(text[0])

        dalao = []
        try:
            found_dalao = soup.find(string=re.compile('^Acknowledgements*')).find_next()
            dalao_text = found_dalao.get_text()
            doc = nlp(dalao_text)
            dalao = [i.text for i in doc.ents if i.label_ == 'PERSON']
            print(dalao_text)
            if not dalao and 'thank' in dalao_text and 'for' in dalao_text:     # 尝试补救一下
                name = dalao_text.split('thank')[1].split('for')[0].split('(').strip()
                dalao.append(name)
                Color.print_failed(name)
        except Exception as e:
            Color.print_failed('Acknowledgements')

        result = {}
        for name in dalao:
            result[name.rsplit(string.digits)[0]] = cve
        if not result:
            Color.print_failed(url)
        return result

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
            flag = 0
            results = []
            tasks = []
            for url in urls:
                tasks.append(executor.submit(Intel.downloadThread, url))
                flag += 1
                # if flag >= 30:
                #     break
            # for task in as_completed(tasks):
            #     result = task.result()
            #     results.append(result)
        # Color.print(results)

    def get_dalao(self):
        pass

    def update_readme(self):
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

        readme = self.root_path.joinpath('README.md')
        with open(readme, 'w+') as f:
            f.write(content)
            Color.print_success(f'[+] update readme: {readme}')
