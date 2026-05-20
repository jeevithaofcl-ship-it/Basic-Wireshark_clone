import socket
import struct

def start_capture():
    print("Packet Capture Started...")

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)

        dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', raw_data[:14])

        print("\nPacket Captured")
        print("Packet Length:", len(raw_data))