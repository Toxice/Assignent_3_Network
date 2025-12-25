import argparse
import socket
from Network_Packets.packet import *
from Network_Packets.packet_type import PacketType
from Utils.configuration import ConnectionConfig
from Network_Utils.mesage_chunker import Chunker


# --- HANDSHAKE ---
def handle_handshake(sock: socket.socket, config: ConnectionConfig) -> bool:
    print("[Client] Starting Handshake...")

    # 1. Send SYN
    syn_packet = HandshakePacket(PacketType.SYN,
                                 config.window_size,
                                 config.message_size,
                                 config.timeout,
                                 config.dynamic)

    print(f"[Client] Sending SYN: {syn_packet.return_dict()}")
    sock.sendall(syn_packet.to_bytes())

    # 2. Receive SYN/ACK
    buff = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        buff += chunk

        if b"\n" in buff:
            line, _, _ = buff.partition(b"\n")
            response = json.loads(line.decode("utf-8"))
            print(f"[Client] Received: {response}")

            if response.get('flag') == PacketType.SYNACK.value:
                # 3. Send ACK
                ack_packet = HandshakeAckPacket(PacketType.ACK)
                print(f"[Client] Sending ACK: {ack_packet.return_dict()}")
                sock.sendall(ack_packet.to_bytes())
                print("[Client] Handshake Complete.")
                return True
            else:
                return False
    return False


# --- DATA TRANSFER ---
def send_packets(sock: socket.socket, packet_list: list[DataPacket], timeout: int, window_size: int):
    total_packets = len(packet_list)
    base = 0
    next_seq_num = 0

    sock.settimeout(timeout)
    print(f"\n[Client] Starting transfer of {total_packets} packets...")

    while base < total_packets:
        # 1. Send packets within the window
        while next_seq_num < base + window_size and next_seq_num < total_packets:
            packet = packet_list[next_seq_num]
            print(f"[Client] Sending Packet (Seq: {packet.sequence}): {packet.return_dict()}")
            sock.sendall(packet.to_bytes())
            next_seq_num += 1

        # 2. Wait for ACKs
        buff = b""
        try:
            while base < next_seq_num:
                if b"\n" in buff:
                    line, _, buff = buff.partition(b"\n")
                    ack_dict = json.loads(line.decode('utf-8'))
                    print(f"[Client] Received ACK: {ack_dict}")

                    if ack_dict.get('flag') == PacketType.ACK.value:
                        ack_seq = ack_dict.get('ack')

                        # Go-Back-N Logic: Move window if correct ACK received
                        if ack_seq == packet_list[base].sequence:
                            base += 1
                    continue

                chunk = sock.recv(4096)
                if not chunk: break
                buff += chunk

        except socket.timeout:
            print("[Client] Timeout! Resending window...")
            next_seq_num = base

    print("[Client] Data Transfer Complete.\n")


# --- TEARDOWN ---
def handle_teardown(sock: socket.socket):
    print("[Client] Initiating Teardown...")
    fin = FinPacket(PacketType.FIN)
    print(f"[Client] Sending FIN: {fin.return_dict()}")
    sock.sendall(fin.to_bytes())

    buff = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        buff += chunk

        if b"\n" in buff:
            line, _, _ = buff.partition(b"\n")
            response = json.loads(line.decode('utf-8'))
            print(f"[Client] Received: {response}")

            if response.get('flag') == PacketType.FINACK.value:
                print("[Client] Received FIN/ACK. Sending Final ACK.")
                ack = HandshakeAckPacket(PacketType.ACK)
                print(f"[Client] Sending Final ACK: {ack.return_dict()}")
                sock.sendall(ack.to_bytes())
                break


# --- MAIN ---
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--config", default="config.txt")
    args = ap.parse_args()

    # Load Config
    try:
        config = ConnectionConfig(args.config)

        # EXPLICITLY READ message.txt (Ignoring config path indirectly)
        print(f"[Client] Reading message content from 'message.txt'...")
        with open("message.txt", "r") as f:
            message_content = f.read()

    except Exception as e:
        print(f"Error reading config or message.txt: {e}")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((args.host, args.port))

        if handle_handshake(sock, config):
            chunker = Chunker(message_content, config.message_size)
            packets = chunker.get_chunk_list()

            send_packets(sock, packets, config.timeout, config.window_size)

            handle_teardown(sock)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()
        print("[Client] Connection Closed.")


if __name__ == "__main__":
    main()