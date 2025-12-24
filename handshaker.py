from packet import HandshakePacket, HandshakeAckPacket
import socket
import json
from packet_type import PacketType

class Handshaker:
    def __init__(self, sock: socket.socket, packet: HandshakePacket, address: tuple):
        self.packet = packet
        self.sock = sock
        self.address = address

    def init_handshake(self) -> HandshakePacket | None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.address)

        # send SYN
        self.sock.sendall(self.packet.to_bytes())

        buffer = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            buffer += chunk

            server_info = json.loads(buffer.decode('utf-8'))
            server_packet = HandshakePacket.json_to_packet(server_info)
            self.sock.sendall(HandshakeAckPacket(PacketType.ACK).to_bytes())
            return server_packet