from Network_Packets.packet import DataPacket
from Network_Packets.packet_type import PacketType


class Chunker:
    def __init__(self, message: str, message_length: int):
        """
        break a single message into multiple chunks and stores each chunk as a DataPacket in the list
        :param message: message from message.txt
        :param message_length: the maximum length of message as defined at config.txt
        """
        self.packet_list: list[DataPacket] = list()

        for i in range(0, len(message), message_length):
            self.packet_list.append(DataPacket(PacketType.PUSH, i, message[i:i + message_length]))

    def get_chunk_list(self) -> list[DataPacket]:
        """
        :return: the chunked list of DataPackets made in __init__
        """
        return self.packet_list