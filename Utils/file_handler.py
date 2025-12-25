from typing import Any

class FileHandler:
    def __init__(self, path: str):
        self.path = path
        self.data = dict()

        with open(self.path, 'r') as f:
            for line in f:
                key, value = line.strip().split(":")
                self.data[key] = value  # or int(value) if needed

    def get_att(self, key: str) -> str | int | bool | None:
        return self.data.get(key)

    def get_message(self) -> str:
        return str(self.data.get("message"))