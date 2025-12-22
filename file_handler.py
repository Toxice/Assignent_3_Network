from typing import Any

class FileHandler:
    def __init__(self, path: str):
        self.path = path
        self.data = dict()

        f = open(self.path, 'r')

        for line in f:
            key, value = line.strip().split(":")
            self.data[key] = value  # or int(value) if needed

    def get_att(self, key: str) -> str | int | None:
        return self.data.get(key)