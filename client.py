# client.py
import argparse, socket, json
from packet import Packet
from file_handler import FileHandler
from packet import *

def handle_handshake(sock: socket.socket, host: str, port: int, packet: HandshakePacket) -> HandshakePacket | None :
    """Send a SYN Packet and Receive SYN.ACK Packet"""

    data = (json.dumps(packet.return_dict(), ensure_ascii=False) + "\n").encode("utf-8")
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

def create_handshake_packet(file_path: str) -> HandshakePacket:
    file_handler = FileHandler(file_path)
    window_size = file_handler.get_att("window_size")
    timeout = file_handler.get_att("timeout")
    maximum_message_size = file_handler.get_att("maximum_msg_size")
    syn_packet = HandshakePacket("SYN", window_size, timeout)
    return syn_packet

def __handshake():
    pass

def main():
    ap = argparse.ArgumentParser(description="Client JSON Reliable Data Transfer over TCP")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--config", type=str, default="config.txt")
    args = ap.parse_args()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((args.host, args.port))
    print(f"[Client] connected to {args.host}:{args.port}")

    #-----create SYN Packet
    syn_packet = create_handshake_packet(args.config)

    handshake_response = handle_handshake(client, args.host, args.port, syn_packet)

    print(handshake_response)

if __name__ == "__main__":
    main()
