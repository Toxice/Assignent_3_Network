# client.py
import argparse, socket, json
import time

from packet import *
from configuration import ConnectionConfig

# we need a loop to send all Data Packets, cause the handle_request method can only send a single packet

def handle_handshake(sock: socket.socket, config_file: str) -> HandshakePacket | None :
    """Send a SYN Packet and Receive SYN.ACK Packet"""
    syn_packet = HandshakePacket.create_handshake_packet(config_file, "SYN")

    data = (json.dumps(syn_packet.return_dict(), ensure_ascii=False) + "\n").encode("utf-8")
    # send SYN to Server
    print("[Client] Sending SYN...")
    sock.sendall(data)

    buff = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buff += chunk
        if b"\n" in buff:
            line, _, _ = buff.partition(b"\n")
            data_dict = json.loads(line.decode("utf-8"))
            packet_out = HandshakePacket.json_to_packet(data_dict)
            if packet_out.flag == "SYN/ACK":
                print(f"[Client] got request: {packet_out}")
                print("[Client] sending ACK....")
                packet_in = HandshakeAckPacket("ACK")
                data_out = (json.dumps(packet_in.return_dict(), ensure_ascii=False) + "\n").encode("utf-8")
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

def loop(message: str, client_config: ConnectionConfig, sock: socket.socket):
    msg_size = client_config.message_size
    packet_list = list()

    for i in range(len(message), msg_size):
        packet_list.append(DataPacket("PUSH", i, message[i:i+msg_size] + '\n'))


def send_packets(packet_list: list, sock: socket.socket, timeout: int, window_size: int):

    for i in range(window_size):
        sock.sendall(packet_list[i])

    sock.settimeout(timeout)
    buff = b""
    line = b"0"
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buff += chunk
        if b"\n" in buff:
            line, _, _ = buff.partition(b"\n")
            for i in range(len(line)):
                data_string = json.loads(line)





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

def main():
    ap = argparse.ArgumentParser(description="Client JSON Reliable Data Transfer over TCP")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--config", type=str, default="config.txt")
    args = ap.parse_args()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((args.host, args.port))
    print(f"[Client] connected to {args.host}:{args.port}")
    # ----- establish the TCP handshake-----------
    client_config = ConnectionConfig(args.config)
    syn_ack_packet = handle_handshake(client, args.config)
    server_config = ConnectionConfig.set_properties_from_file(syn_ack_packet.window, syn_ack_packet.timeout,
                                                              syn_ack_packet.maximum_message_size, syn_ack_packet.dynamic)
    negotiate_connection(server_config, client_config)


if __name__ == "__main__":
    main()
