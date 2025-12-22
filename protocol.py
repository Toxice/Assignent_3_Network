import time
import json
import socket

# Configuration defaults based on your config.txt
MSS = 100  # Maximum Segment Size (bytes per packet)


def create_packets(data: str, start_seq: int) -> list[dict]:
    """
    Splits data into chunks and wraps them in packet dictionaries.
    """
    packets = []
    # Split string into chunks of MSS size
    for i in range(0, len(data), MSS):
        chunk = data[i:i + MSS]
        packets.append({
            "seq": start_seq,
            "data": chunk,
            "len": len(chunk)
        })
        start_seq += 1
    return packets


def calculate_cumulative_ack(received_packets: list[dict], expected_seq: int) -> int:
    """
    Iterates through received packets to find the last continuous sequence number.
    If 1, 2, 4 are received, and expected is 1:
    - 1 matches expected. Expected becomes 2.
    - 2 matches expected. Expected becomes 3.
    - 4 does not match 3. Stop.
    Return 2 (the last valid packet).
    """
    # Sort packets by sequence to handle out-of-order arrival
    sorted_packets = sorted(received_packets, key=lambda x: x['seq'])

    last_valid_ack = expected_seq - 1

    for pkt in sorted_packets:
        if pkt['seq'] == expected_seq:
            last_valid_ack = pkt['seq']
            expected_seq += 1
        elif pkt['seq'] > expected_seq:
            # We found a gap! (e.g. got 4 but expected 3)
            break
        # If pkt['seq'] < expected_seq, it's a duplicate, ignore it

    return last_valid_ack