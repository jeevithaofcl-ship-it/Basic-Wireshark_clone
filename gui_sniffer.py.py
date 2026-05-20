import tkinter as tk
from tkinter import ttk
import socket
import struct
import threading
import csv

# Main Window
root = tk.Tk()
root.title("Wireshark Clone - Major Project")
root.geometry("1000x500")
packet_count=0

selected_filter = tk.StringVar()
selected_filter.set("ALL")

search_ip=tk.StringVar()

sniffing=False

# CSV File Setup
csv_file = open("packets.csv", "w", newline="")

csv_writer = csv.writer(csv_file)

csv_writer.writerow([
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Length",
    ])

# Table Columns
columns = (
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Length"
)

tree = ttk.Treeview(root, columns=columns, show='headings')

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

tree.pack(fill=tk.BOTH, expand=True)
counter_label = tk.Label(
    root,
    text="Packets Captured: 0",
    font=("Arial", 12)
)

counter_label.pack()

filter_menu = tk.OptionMenu(
    root,
    selected_filter,
    "ALL",
    "TCP",
    "UDP"
)

filter_menu.pack()

search_entry = tk.Entry(
    root,
    textvariable=search_ip,
    width=30
)

search_entry.pack()

search_entry.insert(0, "Search IP")

# Packet Capture Function
def start_sniffing():

    global sniffing
    global packet_count

    sniffing=True

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while sniffing:

        raw_data, addr = conn.recvfrom(65536)

        eth_proto = struct.unpack('!H', raw_data[12:14])[0]

        if eth_proto == 0x0800:

            ip_header = raw_data[14:34]

            ttl, proto, src, target = struct.unpack(
                '!8xBB2x4s4s',
                ip_header[:20]
            )

            src_ip = socket.inet_ntoa(src)
            dest_ip = socket.inet_ntoa(target)

            src_port = 0
            dest_port = 0

            if proto == 6:

                protocol = "TCP"

                tcp_header = raw_data[34:54]

                src_port, dest_port = struct.unpack('!HH', tcp_header[:4])

            elif proto == 17:

                protocol = "UDP"

                udp_header = raw_data[34:42]

                src_port, dest_port = struct.unpack('!HH', udp_header[:4])

            else:
                protocol = str(proto)

            # Insert into GUI Table

        if (
       selected_filter.get() == "ALL"
       or selected_filter.get() == protocol
):
            tree.insert(
                "",
                tk.END,
                values=(
                    src_ip,
                    dest_ip,
                    protocol,
                    src_port,
                    dest_port,
                    len(raw_data)
                )
            )
        packet_count += 1

        counter_label.config(
        text=f"Packets Captured: {packet_count}"
)

        csv_writer.writerow([
    src_ip,
    dest_ip,
    protocol,
    src_port,
    dest_port,
    len(raw_data)
])
        
def stop_sniffing():

    global sniffing

    sniffing = False
# Start Button
start_button = tk.Button(
    root,
    text="Start Sniffing",
    command=lambda: threading.Thread(
        target=start_sniffing,
        daemon=True
    ).start()
)

start_button.pack()

# Stop Button
stop_button = tk.Button(
    root,
    text="Stop Sniffing",
    command=stop_sniffing
)

stop_button.pack()

root.mainloop()
