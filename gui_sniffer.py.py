import socket
import struct
import tkinter as tk
from tkinter import ttk

import threading
from datetime import datetime

# GUI setup
root = tk.Tk()
root.title("Wireshark Basic Clone")
root.geometry("900x400")

# Table columns
columns = ("Time", "Source", "Destination", "Protocol", "Src Port", "Dest Port", "Length")
tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=120)

tree.pack(fill=tk.BOTH, expand=True)

# Functions
def ipv4(addr):
    return '.'.join(map(str, addr))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return socket.htons(proto), data[14:]

def ipv4_packet(data):
    
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Sniffer function
def sniff():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:
            ttl, proto, src, target, data = ipv4_packet(data)

            # Port extraction
            src_port = ""
            dest_port = ""
            if proto == 6 or proto == 17:
                src_port, dest_port = struct.unpack('!HH', data[:4])

            # Protocol name
            if proto == 6:
                pname = "TCP"
            elif proto == 17:
                pname = "UDP"
            else:
                pname = "OTHER"

            # Time
            time_now = datetime.now().strftime("%H:%M:%S")

            # Insert into GUI
            tree.insert("", "end", values=(
                time_now, src, target, pname, src_port, dest_port, len(raw_data)
            ))

# Start button
def start_sniffing():
    t = threading.Thread(target=sniff)
    t.daemon = True
    t.start()

btn = tk.Button(root, text="Start Sniffing", command=start_sniffing)
btn.pack()

root.mainloop()