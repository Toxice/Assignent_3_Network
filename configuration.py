from file_handler import FileHandler

class ConnectionConfig:
    def __init__(self, path: str):
        file = FileHandler(path)
        self.window_size = file.get_att("window_size")
        self.message_size = file.get_att("maximum_message_size")
        self.timeout = file.get_att("timeout")
        self.dynamic = file.get_att("dynamic_message_size")

    def get_window_size(self) -> int:
        return self.window_size

    def get_timeout(self) -> int:
        return self.timeout

    def get_message_size(self) -> int:
        return self.message_size

    def get_is_dynamic(self) -> bool:
        return self.dynamic

    def set_properties_from_file(self, window_size, timeout, message_size, dynamic):
        self.window_size = window_size
        self.timeout = timeout
        self.message_size = message_size
        self.dynamic = dynamic