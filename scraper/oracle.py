import sys
import json
from pathlib import Path

sys.path.append('..')
from utils import Color


class Oracle:
    def __init__(self, data_path: Path, download: bool=False) -> None:
        self.data_path = data_path
        if download:
            self.data = self.download()
        else:
            with open(self.data_path.joinpath('acknowledgement.json'), 'r') as f:
                self.data = json.load(f)

    def download(self):
        url = 'https://www.oracle.com/security-alerts'

    def get_dalao(self):
        pass

    def update_readme(self):
        pass
