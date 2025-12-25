from Network_Packets.packet import DataPacket
import socket


class Framer:
    """
    class made to frame a number of DataPackets inside a sliding window
    """
    def __init__(self, sock: socket.socket, packet_list: list, window_size: int, timeout: int):
        self.sock = sock
        self.packet_list = packet_list
        self.window_size = window_size
        self.window_frame: list[DataPacket] = list()
        self.timeout = timeout
        self.next_window_index = 0

    def __set_window_by_packet_list(self):
        """
        set as many packets as you can in the window
        """
        for i in range(self.window_size):
            self.window_frame.append(self.packet_list[i])
            self.next_window_index += 1

    def send_window(self):
        self.__set_window_by_packet_list()

        for i in range(len(self.window_frame)):
            self.sock.sendall(self.window_frame[i].to_bytes())
            print(f"[Client] sent packet with sequence num:{self.window_frame[i].sequence}")
        sock.settimeout(self.timeout)