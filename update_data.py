#!/usr/bin/python3

import json
import requests
from lxml import etree
from colorama import Fore
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class Color:
    @staticmethod
    def print_focus(data: str):
        print(Fore.YELLOW+data+Fore.RESET)

    @staticmethod
    def print_success(data: str):
        print(Fore.LIGHTGREEN_EX+data+Fore.RESET)

    @staticmethod
    def print_failed(data: str):
        print(Fore.LIGHTRED_EX+data+Fore.RESET)


class Apple:
    def __init__(self, data_path: Path, download: bool=False) -> None:
        self.data_path = data_path
        if download:
            self.data = self.download()
        else:
            with open(self.data_path.joinpath('acknowledgement.json'), 'r') as f:
                self.data = json.load(f)

    def download():
        pass

    def get_dalao():
        pass


class Google:
    def __init__(self, data_path: Path, download: bool=False) -> None:
        self.data_path = data_path
        if download:
            self.data = self.download()
        else:
            with open(self.data_path.joinpath('acknowledgement.json'), 'r') as f:
                self.data = json.load(f)

    def download():
        pass

    def get_dalao():
        pass


class Oracle:
    def __init__(self, data_path: Path, download: bool=False) -> None:
        self.data_path = data_path
        if download:
            self.data = self.download()
        else:
            with open(self.data_path.joinpath('acknowledgement.json'), 'r') as f:
                self.data = json.load(f)

    def download():
        pass

    def get_dalao():
        pass


class Microsoft:
    def __init__(self, data_path: Path, download: bool=False) -> None:
        self.data_path = data_path
        if download:
            self.data = self.download()
        else:
            with open(self.data_path.joinpath('acknowledgement.json'), 'r') as f:
                self.data = json.load(f)

    def download(self):
        start_date = '2016-01-01'
        end_date = datetime.now().strftime('%Y-%m-%d')

        result = []
        for skip in range(0, 100000, 500):
            url = f'https://api.msrc.microsoft.com/sug/v2.0/en-US/acknowledgement?$orderby=releaseDate desc&$filter=(releaseDate gt {start_date}T00%3A00%3A00%2B08%3A00) and (releaseDate lt {end_date}T23%3A59%3A59%2B08%3A00)&$skip={skip}'
            value = requests.get(url).json()['value']
            if value:
                result += value
            else:
                break
        with open(self.data_path.joinpath('acknowledgement.json'), 'w+') as f:
            f.write(json.dumps(result, indent=4))

        return result


    def get_dalao(self, acktype: str):
        """取值 Finder/Online/DiD"""

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
                dalao[name]['url'] = [url]
                dalao[name]['cve'] = [cve]

        type_data = []
        for item in self.data:
            if item['ackType'] == acktype:
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

        return dalao


if __name__ == '__main__':
    plugin = {
        'microsoft': True,
        'apple': False,
        'google': False,
        'oracle': False
    }

    if plugin['microsoft']:
        data_path = Path(__file__).parent.joinpath('microsoft/data')
        m = Microsoft(data_path, download=True)

        dalao = m.get_dalao('Finder')
        with open(data_path.joinpath('dalao.json'), 'w+') as f:
            f.write(json.dumps(dalao, indent=4))

    if plugin['apple']:
        data_path = Path(__file__).parent.joinpath('apple/data')
        #TODO

    if plugin['google']:
        data_path = Path(__file__).parent.joinpath('google/data')
        # TODO

    if plugin['oracle']:
        data_path = Path(__file__).parent.joinpath('oracle/data')
        # TODO
