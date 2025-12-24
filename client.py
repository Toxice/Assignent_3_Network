# client.py
import argparse, socket, json
import time

from packet import *
from configuration import ConnectionConfig
from mesage_chunker import Chunker
from handshaker import Handshaker

# we need a loop to send all Data Packets, cause the handle_request method can only send a single packet

def handle_handshake(sock: socket.socket, config_file: str) -> HandshakePacket | None :
    """Send a SYN Packet and Receive SYN.ACK Packet"""
    syn_packet = HandshakePacket.create_handshake_packet(config_file, "SYN")

    data = (json.dumps(syn_packet.return_dict(), ensure_ascii=False) + "*").encode("utf-8")
    # send SYN to Server
    print("[Client] Sending SYN...")
    sock.sendall(data)

    buff = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buff += chunk
        if b"*" in buff:
            line, _, _ = buff.partition(b"*")
            data_dict = json.loads(line.decode("utf-8"))
            packet_out = HandshakePacket.json_to_packet(data_dict)
            if packet_out.flag == "SYN/ACK":
                print(f"[Client] got request: {packet_out}")
                print("[Client] sending ACK....")
                packet_in = HandshakeAckPacket("ACK")
                data_out = (json.dumps(packet_in.return_dict(), ensure_ascii=False) + "*").encode("utf-8")
                sock.sendall(data_out)
                return packet_out

            else:
                print("[Client] didn't got SYN/ACK...Handshake Failed")
                return None


def handle_response(packet_window: list[DataPacket]):
    """
    takes all Data Packets of the Client and Send them over the Socket
    :param packet_window: the list of the Data Packets of the Client
    """
    pass


def handle_request(server_packet_window: list[DataPacket]) -> AckPacket:
    """
    handles window framing and timing
    if a window is missing one or more DataPacket, the Server should inform the Client by sending ACK
    of the last Data Packet it got.
    for example: if our window has DataPackets from sequence number 5 till 10, but is missing sequence
    number 8, we should send ACK about sequence number 7 (cause that the last Packet up until 8 we got)
    :param server_packet_window: window (list) of Data Packets
    :return: the response DataPacket Window (list of Data Packets)
    """

    started = time.time()

    #---------build Message Flow---------

    took = int((time.time()-started)*1000)
    pass

def message_to_chunks(message: str, max_message_size: int) -> list[DataPacket]:
    packet_list = list()

    for i in range(0, len(message), max_message_size):
        packet_list.append(DataPacket("PUSH", i, message[i:i+max_message_size]))
    return packet_list

def __send_chunks(packet_list: list[DataPacket], sock: socket.socket, window_size: int):
    for i in range(window_size):
        sock.sendall(json.dumps(packet_list[i].return_dict()).encode('utf-8'))


# def send_packets(packet_list: list, sock: socket.socket, timeout: int, window_size: int):
#
#     __send_chunks(packet_list, sock, window_size)
#     sliding_window = list()
#
#     sock.settimeout(timeout)
#
#     # We use a string buffer because JSON works on strings
#     buff = ""
#     decoder = json.JSONDecoder()
#
#     while True:
#         try:
#             chunk = sock.recv(4096)
#             if not chunk:
#                 break
#
#             # Decode bytes to string and append to buffer
#             buff += chunk.decode('utf-8')
#
#             # Continuously parse valid objects from the buffer
#             while buff:
#                 try:
#                     # raw_decode returns a tuple: (python_dict, end_index)
#                     packet, next_index = decoder.raw_decode(buff)
#                     if len(sliding_window) < window_size:
#                         sliding_window.append(packet)
#                         print(f"Received packet: {packet}")
#
#                     # Logic to handle sliding window / ACKs goes here...
#                     if len(sliding_window) == window_size:
#                         last_acked_packet = send_ack_per_packet(sliding_window).return_dict()
#                         sock.sendall(json.dumps(last_acked_packet).encode('utf-8'))
#
#                     # SLICE THE BUFFER: Remove the parsed object
#                     # .lstrip() removes any accidental whitespace between packets
#                     buff = buff[next_index:].lstrip()
#
#                 except json.JSONDecodeError:
#                     # We have data, but it's not a complete JSON object yet.
#                     # Break inner loop and wait for more data from sock.recv()
#                     break
#
#         except socket.timeout:
#             print("Socket timed out")
#             break


# client.py

def send_packets(packet_list: list[DataPacket], sock: socket.socket, timeout: int, window_size: int):
    """
    Stop-and-Wait / Go-Back-N Hybrid for demonstration.
    Simple logic: Send window -> Wait for ALL ACKs -> If timeout/fail, resend unacked.
    """
    total_packets = len(packet_list)
    base = 0  # The first un-acked packet
    next_seq_num = 0

    sock.settimeout(timeout)
    decoder = json.JSONDecoder()
    buff = ""

    while base < total_packets:
        # 1. Send packets within the window
        while next_seq_num < base + window_size and next_seq_num < total_packets:
            print(f"[Client] Sending Packet Seq: {packet_list[next_seq_num].sequence}")
            sock.sendall((json.dumps(packet_list[next_seq_num].return_dict())).encode('utf-8'))
            next_seq_num += 1

        # 2. Wait for ACKs
        try:
            chunk = sock.recv(4096)
            if not chunk: break
            buff += chunk.decode('utf-8')

            while buff:
                try:
                    # Parse incoming ACK
                    response, idx = decoder.raw_decode(buff)
                    buff = buff[idx:].lstrip()

                    # Convert to AckPacket
                    ack_packet = AckPacket.json_to_packet(response)

                    if ack_packet.flag == "ACK":
                        print(f"[Client] Received ACK for {ack_packet.ack}")
                        # If we get an ACK for the packet at 'base', we can slide the window
                        # Assuming Cumulative ACK (ACK N means "I have received everything up to N")
                        # You might need to adjust this depending on if your server sends ACK N for packet N
                        # or ACK N+1 (TCP style).
                        # Based on your previous code, let's assume ACK N means "I got packet N".

                        if ack_packet.ack >= packet_list[base].sequence:
                            # Slide window forward
                            packets_acked = (ack_packet.ack - packet_list[base].sequence) + 1
                            # Logic depends on your Sequence ID strategy (0, 1, 2 vs 0, 100, 200)
                            # Assuming index-based sequence for simplicity here:

                            # Find where this sequence number is in our list
                            # (Simplification: assuming seq num matches list index)
                            if ack_packet.ack >= base:
                                base = ack_packet.ack + 1

                except json.JSONDecodeError:
                    break

        except socket.timeout:
            print("[Client] Timeout! Resending window...")
            next_seq_num = base  # Reset to base to resend

    print("[Client] File Transfer Complete.")


def main():
    ap = argparse.ArgumentParser(description="Client JSON Reliable Data Transfer over TCP")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--config", type=str, default="config.txt")
    args = ap.parse_args()

    host = args.host
    port = args.port
    address = (host, port)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    message = FileHandler(args.config).get_message()
    client_config = ConnectionConfig(args.config)
    server_config = ConnectionConfig(args.config)
    try:
        client.connect((args.host, args.port))
        print(f"[Client] connected to {args.host}:{args.port}")

        # 1. Handshake
        message_chunker = Chunker(message, client_config.message_size)
        handshake_syn = HandshakePacket(PacketType.SYN,
                                        client_config.window_size,
                                        client_config.message_size,
                                        client_config.timeout,
                                        client_config.dynamic)
        syn_ack_packet = Handshaker(client, handshake_syn, address).init_handshake()

        chunked_message: list = message_chunker.get_chunk_list()

        client.sendall(handshake_syn.to_bytes())

        if not syn_ack_packet:
            print("Handshake failed.")
            return

        # 2. Config

        negotiate_connection(server_config, client_config)

        # 3. Prepare Data
        # Fix: ensure message is read correctly
        packets = message_to_chunks(message, client_config.message_size)

        # 4. Send Data
        print(f"[Client] Starting transfer of {len(packets)} packets...")
        send_packets(packets, client, client_config.timeout, client_config.window_size)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    main()



def send_ack_per_packet(sliding_window: list[DataPacket]) -> AckPacket:
    # sorting automatically by the sequence number of each packet
    sliding_window.sort()
    message = str()
    for i in range(len(sliding_window) -1):
        # meaning - if the i-th packet sequence number and the next packet has sequential sequence numbers
        # keep the payload
        if sliding_window[i].sequence - sliding_window[i+1].sequence == 1:
            message += sliding_window[i].payload
            print(f"[Client] Send ACK on packet sequence: {sliding_window[i].sequence}")
        elif sliding_window[i].sequence - sliding_window[i+1].sequence > 1:
            print(f"[Client] didn't got Packet by sequence number: {sliding_window[i].sequence}")
            return AckPacket("ACK", sliding_window[i].sequence)
    return AckPacket("ACK", len(sliding_window) - 1)



# def request(host: str, port: int, packet: Packet) -> dict:
#     """Send a single JSON-line request and return a single JSON-line response."""
#     data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
#     with socket.create_connection((host, port), timeout=5) as s:
#         # send SYN to Server
#         s.sendall(data)
#         buff = b""
#         while True:
#             chunk = s.recv(4096)
#             if not chunk:
#                 break
#             buff += chunk
#             if b"\n" in buff:
#                 line, _, _ = buff.partition(b"\n")
#                 return json.loads(line.decode("utf-8"))
#     return {"ok": False, "error": "No response"}


def negotiate_connection(server_config: ConnectionConfig, client_config: ConnectionConfig):
    window_size = server_config.window_size if server_config.window_size > client_config.window_size else client_config.window_size
    msg_size = server_config.message_size if server_config.message_size > client_config.message_size else client_config.message_size
    client_config.window_size = window_size
    client_config.message_size = msg_size

# def main():
#     ap = argparse.ArgumentParser(description="Client JSON Reliable Data Transfer over TCP")
#     ap.add_argument("--host", default="127.0.0.1")
#     ap.add_argument("--port", type=int, default=5555)
#     ap.add_argument("--config", type=str, default="config.txt")
#     args = ap.parse_args()
#
#     client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client.connect((args.host, args.port))
#     print(f"[Client] connected to {args.host}:{args.port}")
#     # ----- establish the TCP handshake-----------
#     client_config = ConnectionConfig(args.config)
#     syn_ack_packet = handle_handshake(client, args.config)
#     server_config = ConnectionConfig.set_properties_from_file(syn_ack_packet.window, syn_ack_packet.timeout,
#                                                               syn_ack_packet.maximum_message_size, syn_ack_packet.dynamic)
#     negotiate_connection(server_config, client_config)
#
#     message = FileHandler(args.config).get_message()


if __name__ == "__main__":
    main()
