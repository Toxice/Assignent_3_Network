import socket
import argparse
from Network_Packets.packet import *
from Network_Packets.packet_type import PacketType


class Server:
    def __init__(self, host, port, config_path):
        self.address = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.address)
        self.sock.listen(1)
        self.config_path = config_path
        print(f"[Server] Listening on {host}:{port}")

    def start(self):
        conn, addr = self.sock.accept()
        print(f"[Server] Connection from {addr}")

        try:
            buffer = b""
            # 1. Handshake Phase
            success, buffer = self.handle_handshake(conn, buffer)
            if not success:
                return

            # 2. Data Transfer Phase
            self.handle_transfer(conn, buffer)

        except Exception as e:
            print(f"[Server] Error: {e}")
        finally:
            conn.close()
            self.sock.close()
            print("[Server] Connection closed.")

    def _recv_packet(self, conn, buffer):
        """Helper to get exactly one packet line"""
        while b"\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk: return None, buffer
            buffer += chunk

        line, _, buffer = buffer.partition(b"\n")
        return line, buffer

    def handle_handshake(self, conn: socket.socket, buffer: bytes) -> tuple[bool, bytes]:
        print("[Server] Waiting for Handshake...")

        # Expect SYN
        line, buffer = self._recv_packet(conn, buffer)
        if not line: return False, buffer

        syn_packet_dict = json.loads(line.decode('utf-8'))
        print(f"[Server] Received Packet: {syn_packet_dict}")

        if syn_packet_dict.get('flag') == PacketType.SYN.value:
            # Send SYN/ACK
            syn_ack = HandshakePacket(PacketType.SYNACK, window=4, maximum_message_size=1024, timeout=5,
                                      dynamic_size=False)
            print(f"[Server] Sending SYN/ACK: {syn_ack.return_dict()}")
            conn.sendall(syn_ack.to_bytes())

            # Expect ACK
            line, buffer = self._recv_packet(conn, buffer)
            if not line: return False, buffer

            ack_dict = json.loads(line.decode('utf-8'))
            print(f"[Server] Received Packet: {ack_dict}")

            if ack_dict.get('flag') == PacketType.ACK.value:
                print("[Server] Handshake Complete.")
                return True, buffer

        return False, buffer

    def handle_transfer(self, conn: socket.socket, buffer: bytes):
        expected_sequence = 0
        received_payload = ""

        while True:
            line, buffer = self._recv_packet(conn, buffer)
            if not line: break

            try:
                data_dict = json.loads(line.decode('utf-8'))
                flag = data_dict.get('flag')
                print(f"[Server] Received Packet: {data_dict}")

                # --- FIN ---
                if flag == PacketType.FIN.value:
                    print("[Server] Sending FIN/ACK...")
                    fin_ack = FinPacket(PacketType.FINACK)
                    conn.sendall(fin_ack.to_bytes())
                    print(f"[Server] Sent: {fin_ack.return_dict()}")

                    # Wait for Final ACK
                    line, buffer = self._recv_packet(conn, buffer)
                    if line:
                        ack_dict = json.loads(line.decode('utf-8'))
                        print(f"[Server] Received Final ACK: {ack_dict}")

                    self.save_message(received_payload)
                    break

                # --- PUSH (Data) ---
                elif flag == PacketType.PUSH.value:
                    seq = data_dict.get('sequence')
                    payload = data_dict.get('payload')

                    if seq == expected_sequence:
                        received_payload += payload
                        # Send ACK
                        ack = AckPacket(PacketType.ACK, seq)
                        conn.sendall(ack.to_bytes())
                        print(f"[Server] Sent ACK: {ack.return_dict()}")

                        expected_sequence += len(payload)
                    else:
                        print(f"[Server] Out of order! Expected {expected_sequence}, got {seq}. Ignoring.")

            except json.JSONDecodeError:
                print("[Server] JSON Error, skipping packet")

    def save_message(self, payload):
        with open("server_output.txt", "w") as f:
            f.write(payload)
        print(f"[Server] Message content saved to server_output.txt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--config", default="config.txt")
    args = parser.parse_args()

    server = Server(args.host, args.port, args.config)
    server.start()