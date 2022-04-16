import copy
import pprint
from colorama import Fore


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

    @staticmethod
    def print(data):
        pprint.pprint(data)


class Readme:
    @staticmethod
    def get_dalao_top(dalao: dict, num: int) -> list({str, dict}):
        """取出top大佬"""
        dalao_top = sorted(list(dalao.items()), key=lambda r: len(r[1]['cve']), reverse=True)
        return dalao_top[:num]

    @staticmethod
    def make_table(dalao: list):
        """Markdown表格"""
        content = ''
        for idx, (name, value) in enumerate(dalao):
            if value['url']:
                content += f'| {idx+1} | [{name}]({value["url"][0]}) | {len(value["cve"])} |\n'
            else:
                content += f'| {idx+1} | {name} | {len(value["cve"])} |\n'
        return content

    @staticmethod
    def get_first_year(dalao: dict) -> int:
        """找到最早的年份"""
        cve = []
        for v in dalao.values():
            cve += v['cve']
        first_year = sorted(cve)[0].split('-')[1]
        return int(first_year)

    @staticmethod
    def get_year_dalao(dalao: dict, year: int) -> dict:
        """取出年度大佬"""
        temp = copy.deepcopy(dalao)
        for v in list(temp.items()):
            if new_cve := [cve for cve in v[1]['cve'] if cve.startswith(f'CVE-{year}')]:
                temp[v[0]]['cve'] = new_cve
            else:
                temp.pop(v[0])
        return temp
