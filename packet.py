from abc import ABC, abstractmethod
import json

class Packet(ABC):
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
    def __init__(self, flag: str, window: str | int, timeout):
        super().__init__(flag)
        self.window = window
        self.timeout = timeout

    def return_dict(self) -> dict:
            return {
                "flag": self.flag,
                "window_size": self.window,
                "timeout": self.timeout
            }

    def __str__(self):
        return json.dumps(self.return_dict())

    @staticmethod
    def json_to_packet(json_dict: dict) -> HandshakePacket:
        flag = json_dict.get('flag')
        window = json_dict.get('window_size')
        timeout = json_dict.get('timeout')
        packet = HandshakePacket(flag, window, timeout)
        return packet


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
    def __init__(self, flag: str, sequence, payload):
        super().__init__(flag)
        self.sequence = sequence
        self.payload = payload

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