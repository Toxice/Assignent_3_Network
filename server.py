# server.py

import argparse, socket, json, time, threading, math, os, ast, operator, collections
from typing import Any, Dict
from file_handler import FileHandler
from packet import *


def handle_handshake(sock: socket.socket, host: str, port: int, packet: HandshakePacket) -> HandshakePacket | None :
    """Send a SYN Packet and Receive SYN.ACK Packet"""
    while True:
        conn, addr = sock.accept()
        print(f"[Server] client connected on {addr}")
        data = (json.dumps(packet.return_dict(), ensure_ascii=False) + "\n").encode("utf-8")
        # send SYN to Server
        buff = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buff += chunk
            if b"\n" in buff:
                line, _, _ = buff.partition(b"\n")
                data_dict = json.loads(line.decode("utf-8"))
                packet_out = HandshakePacket.json_to_packet(data_dict)
                if packet_out.flag == "SYN":
                    print(f"[Server] got request: {packet_out}")
                    print("[Server] sending SYN/ACK....")
                    data_out = (json.dumps(packet.return_dict(), ensure_ascii=False) + "\n").encode("utf-8")
                    conn.sendall(data_out)
                    return packet_out

                else:
                    print("[Client] didn't got SYN/ACK...Handshake Failed")
                    return None


# ---------------- Server core ----------------
def handle_request(msg: Dict[str, Any]) -> Dict[str, Any]:
    mode = msg.get("flag")
    data = msg.get("data") or None
    sequence = msg.get("sequence") or None
    ack = msg.get("ack") or None

    started = time.time()

    #---------build Message Flow---------


    took = int((time.time()-started)*1000)


def serve(host: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(16)
        print(f"[server] listening on {host}:{port}")
        #------handle handshake-----


        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def handle_client(conn: socket.socket, addr):
    with conn:
        try:
            raw = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if b"\n" in raw:
                    line, _, rest = raw.partition(b"\n")
                    raw = rest
                    msg = json.loads(line.decode("utf-8"))
                    resp = handle_request(msg)
                    out = (json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8")
                    conn.sendall(out)
                    break
        except Exception as e:
            try:
                conn.sendall((json.dumps({"ok": False, "error": f"Malformed: {e}"} ) + "\n").encode("utf-8"))
            except Exception:
                pass

def create_handshake_packet(file_path: str) -> HandshakePacket:
    file_handler = FileHandler(file_path)
    window_size = file_handler.get_att("window_size")
    timeout = file_handler.get_att("timeout")
    maximum_message_size = file_handler.get_att("maximum_msg_size")
    syn_packet = HandshakePacket("SYN/ACK", window_size, timeout)
    return syn_packet

def main():
    ap = argparse.ArgumentParser(description="Server JSON Reliable Data Transfer over TCP")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--config", type=str, default="config.txt")
    args = ap.parse_args()

    # -----create SYN Packet
    syn__ack_packet = create_handshake_packet(args.config)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(16)
    print(f"[Server] listening on {args.host}:{args.port}...")

    handshake_response = handle_handshake(server, args.host, args.port, syn__ack_packet)

    print(handshake_response)

if __name__ == "__main__":
    main()
