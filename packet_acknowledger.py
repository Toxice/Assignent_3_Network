import socket
from packet import DataPacket, AckPacket
from packet_type import PacketType
from window_framer import Framer
import json
from collections import deque

class PacketAcknowledger:
    def __init__(self, sock: socket.socket, timeout: int):
        self.received_list: list[str] = list()
        self.ack_list: list[DataPacket] = list()
        self.sock = sock
        self.timeout = timeout
        self.packet_queue = deque


    def ack_sent_packets(self):
        """
        count the send packets, sort them and start counting.
        if there's a packet who was not sent - send ACK only for the packets that arrived before it,
        ignoring the rest.
        for example:
        assume we are sending a window of 10 packets, sequenced 5 till 15.
        after sorting we start counting and notice we're missing packet sequence 9.
        meaning - store packets 5 till 8 and 10 till 15 and
        send ACK8 (signaling we got everything from Packet5 till Packet 8
        """
        buffer = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            buffer += chunk

            if "\n" in buffer.decode('utf-8'):
                self.received_list = buffer.decode('utf-8').split("\n")

        for packet in self.received_list:
            self.ack_list.append(json.loads(packet))

        self.ack_list.sort()
        for i in range(len(self.ack_list) - 1):
            if self.ack_list[i].sequence - self.ack_list[i+1].sequence == 1:
                print(f"[Client] got packet sequence {self.ack_list[i].sequence}")
            elif self.ack_list[i].sequence - self.ack_list[i+1].sequence != 1:
                print(f"[Client] got all Packets till {self.ack_list[i].sequence}"
                      f", Sending ACK number {self.ack_list[i].sequence}")
                last_ack_packet = AckPacket(PacketType.ACK, self.ack_list[i].sequence)
                self.sock.sendall(last_ack_packet.to_bytes())
                self.sock.settimeout(self.timeout)
