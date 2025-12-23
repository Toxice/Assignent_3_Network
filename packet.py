from abc import ABC, abstractmethod
import json

from configuration import ConnectionConfig
from file_handler import FileHandler


class Packet(ABC):
    """
    Abstract Class made to model a Packet
    """
    def __init__(self, flag: str):
        self.flag = flag
        self.data = {
            "flag": self.flag
        }

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def return_dict(self) -> dict:
        pass


class HandshakePacket(Packet):
    def __init__(self, flag: str, window: int, maximum_message_size: int, timeout: int, dynamic_size: bool):
        super().__init__(flag)
        self.window = window
        self.maximum_message_size = maximum_message_size
        self.timeout = timeout
        self.dynamic = dynamic_size

    def return_dict(self) -> dict:
            return {
                "flag": self.flag,
                "window_size": self.window,
                "maximum_msg_size": self.maximum_message_size,
                "timeout": self.timeout,
                "dynamic_size": self.dynamic
            }

    def __str__(self):
        return json.dumps(self.return_dict())

    @staticmethod
    def json_to_packet(json_dict: dict) -> HandshakePacket:
        flag = json_dict.get('flag')
        window = json_dict.get('window_size')
        maximum_message_size = json_dict.get('maximum_msg_size')
        timeout = json_dict.get('timeout')
        dynamic = json_dict.get('dynamic')
        packet = HandshakePacket(flag, window, maximum_message_size, timeout, dynamic)
        return packet

    @staticmethod
    def create_handshake_packet(config_file: str, flag: str) -> HandshakePacket:
        """
        Create the initial SYN Packet
        :param config_file: ConnectionConfig File
        :param flag: type of Packet flag (SYN or SYN/ACK)
        :return: HandshakePacket
        """
        file = FileHandler(config_file)
        return HandshakePacket(flag, file.get_att("window_size"), file.get_att("maximum_msg_size"), file.get_att("timeout")
                               , file.get_att("dynamic_size"))


class FinPacket(Packet):
    def __init__(self, flag: str):
        super().__init__(flag)

    def __str__(self):
        return json.dumps(self.return_dict())

    @staticmethod
    def json_to_packet(json_dict: dict) -> FinPacket:
        flag = json_dict.get('flag')
        packet = FinPacket(flag)
        return packet

    def return_dict(self) -> dict:
        return {
            "flag": self.flag
        }

class DataPacket(Packet):
    def __init__(self, flag: str, sequence: int, payload: str):
        super().__init__(flag)
        self.sequence = sequence
        self.payload = payload

    def __eq__(self, other: DataPacket):
        if self.sequence == other.sequence:
            return True
        else:
            return False
    def __lt__(self, other: DataPacket):
        if self.sequence < other.sequence:
            return True
        else:
            return False
    def __gt__(self, other: DataPacket):
        if self.sequence > other.sequence:
            return True
        else:
            return False

    def __str__(self):
        return json.dumps(self.return_dict())

    def return_dict(self) -> dict:
        return {
            "flag": self.flag,
            "sequence": self.sequence,
            "payload": self.payload
            }

    @staticmethod
    def json_to_packet(json_dict: dict) -> DataPacket:
        flag = json_dict.get('flag')
        sequence = json_dict.get('sequence')
        payload = json_dict.get('payload')
        packet = DataPacket(flag, sequence, payload)
        return packet

class AckPacket(Packet):
    def __init__(self, flag: str, ack: int):
        super().__init__(flag)
        self.ack = ack

    def __str__(self):
        return json.dumps(self.return_dict())

    def return_dict(self) -> dict:
        return {
            "flag": self.flag,
            "ack": self.ack
        }

    @staticmethod
    def json_to_packet(json_dict: dict) -> AckPacket:
        flag = json_dict.get('flag')
        ack = json_dict.get('ack')
        packet = AckPacket(flag, ack)
        return packet


class HandshakeAckPacket(Packet):
    def __init__(self, flag: str):
        super().__init__(flag)

    @staticmethod
    def json_to_packet(json_dict: dict) -> HandshakeAckPacket:
        flag = json_dict.get('flag')
        packet = HandshakeAckPacket(flag)
        return packet

    def return_dict(self) -> dict:
            return {
                "flag": self.flag
            }

    def __str__(self):
        return json.dumps(self.return_dict())