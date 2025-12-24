# configuration.py

from file_handler import FileHandler

class ConnectionConfig:
    def __init__(self, path: str):
        file = FileHandler(path)
        # Force integer casting here
        self.window_size = int(file.get_att("window_size"))
        self.message_size = int(file.get_att("maximum_msg_size"))  # Fixed key name to match config.txt
        self.timeout = int(file.get_att("timeout"))

        # specific check for boolean
        dyn = bool(file.get_att("dynamic_message_size"))
        self.dynamic = True if str(dyn).lower() == "true" else False

    def get_window_size(self) -> int:
        return self.window_size

    def get_timeout(self) -> int:
        return self.timeout

    def get_message_size(self) -> int:
        return self.message_size

    def get_is_dynamic(self) -> bool:
        return self.dynamic