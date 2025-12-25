from abc import ABC, abstractmethod
import json
from Utils.file_handler import FileHandler
from Network_Packets.packet_type import PacketType


class Packet(ABC):
    def __init__(self, flag: PacketType):
        self.flag = flag

    @abstractmethod
    def return_dict(self) -> dict:
        pass

    @abstractmethod
    def to_bytes(self) -> bytes:
        pass


class HandshakePacket(Packet):
    def __init__(self, flag: PacketType, window: int, maximum_message_size: int, timeout: int, dynamic_size: bool):
        super().__init__(flag)
        self.window = int(window)
        self.maximum_message_size = int(maximum_message_size)
        self.timeout = int(timeout)
        self.dynamic = bool(dynamic_size)

    def return_dict(self) -> dict:
        return {
            "flag": self.flag.value if isinstance(self.flag, PacketType) else self.flag,
            "window_size": self.window,
            "maximum_msg_size": self.maximum_message_size,
            "timeout": self.timeout,
            "dynamic_size": self.dynamic
        }

    def to_bytes(self) -> bytes:
        return (json.dumps(self.return_dict()) + "\n").encode('utf-8')

    @staticmethod
    def json_to_packet(json_dict: dict):
        return HandshakePacket(
            json_dict.get('flag'),
            json_dict.get('window_size'),
            json_dict.get('maximum_msg_size'),
            json_dict.get('timeout'),
            json_dict.get('dynamic_size')
        )

    @staticmethod
    def create_handshake_packet(config_file: str, flag: PacketType):
        file = FileHandler(config_file)
        return HandshakePacket(
            flag,
            file.get_att("window_size"),
            file.get_att("maximum_msg_size"),
            file.get_att("timeout"),
            file.get_att("dynamic_message_size") == "True"
        )


class DataPacket(Packet):
    def __init__(self, flag: PacketType, sequence: int, payload: str):
        super().__init__(flag)
        self.sequence = sequence
        self.payload = payload

    def return_dict(self) -> dict:
        return {
            "flag": self.flag.value if isinstance(self.flag, PacketType) else self.flag,
            "sequence": self.sequence,
            "payload": self.payload
        }

    def to_bytes(self) -> bytes:
        return (json.dumps(self.return_dict()) + "\n").encode('utf-8')

    @staticmethod
    def json_to_packet(json_dict: dict):
        return DataPacket(json_dict.get('flag'), json_dict.get('sequence'), json_dict.get('payload'))


class AckPacket(Packet):
    def __init__(self, flag: PacketType, ack: int):
        super().__init__(flag)
        self.ack = ack

    def return_dict(self) -> dict:
        return {"flag": self.flag.value if isinstance(self.flag, PacketType) else self.flag, "ack": self.ack}

    def to_bytes(self) -> bytes:
        return (json.dumps(self.return_dict()) + "\n").encode('utf-8')

    @staticmethod
    def json_to_packet(json_dict: dict):
        return AckPacket(json_dict.get('flag'), json_dict.get('ack'))


class HandshakeAckPacket(Packet):
    def __init__(self, flag: PacketType):
        super().__init__(flag)

    def return_dict(self) -> dict:
        return {"flag": self.flag.value if isinstance(self.flag, PacketType) else self.flag}

    def to_bytes(self) -> bytes:
        return (json.dumps(self.return_dict()) + "\n").encode('utf-8')


class FinPacket(Packet):
    def __init__(self, flag: PacketType):
        super().__init__(flag)

    def return_dict(self) -> dict:
        return {"flag": self.flag.value if isinstance(self.flag, PacketType) else self.flag}

    def to_bytes(self) -> bytes:
        return (json.dumps(self.return_dict()) + "\n").encode('utf-8')