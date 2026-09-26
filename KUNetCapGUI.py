import tkinter as tk
import threading
import time
import wmi
import psutil
from tkinter import ttk, filedialog, messagebox  # ← Add filedialog and messagebox
from scapy.all import Ether, IP, UDP, TCP, Raw, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.all import sniff, PcapWriter
from scapy.all import rdpcap
from scapy.all import raw


def get_interfaces():
    wmi_obj = wmi.WMI()
    interfaces = []
    seen = set()

    for nic in wmi_obj.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        name = nic.Description
        ip = nic.IPAddress[0] if nic.IPAddress else "0.0.0.0"

        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address == ip and iface not in seen:
                    interfaces.append(f"{iface} - {ip}")
                    seen.add(iface)

    return interfaces


# Supported protocol numbers mapped to names
protocol_map = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    89: "OSPF",
    47: "GRE",
    50: "ESP",
    51: "AH"
    # Add more protocol numbers here as needed
}

def get_info(packet):
    try:
        if TCP in packet:
            tcp = packet[TCP]
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x20: flags.append("URG")
            flag_str = ", ".join(flags)
            return f"{tcp.sport} → {tcp.dport} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(tcp.payload)}"
        elif UDP in packet:
            udp = packet[UDP]
            return f"{udp.sport} → {udp.dport} Len={len(udp.payload)}"
        elif ICMP in packet:
            icmp = packet[ICMP]
            return f"ICMP Type={icmp.type} Code={icmp.code} Len={len(icmp.payload)}"
        elif ARP in packet:
            arp = packet[ARP]
            return f"ARP {arp.psrc} → {arp.pdst} op={arp.op}"
        elif IP in packet:
            ip = packet[IP]
            return f"{ip.src} → {ip.dst} Proto={ip.proto} Len={len(ip.payload)}"
        elif Ether in packet:
            eth = packet[Ether]
            return f"Ether Type={hex(eth.type)} Src={eth.src} Dst={eth.dst}"
        else:
            return "Unknown or Unsupported Protocol"
    except Exception as e:
        return f"Error parsing packet: {e}"

class KUNetCapGUI(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.configure(bg="aqua")
        self.packets = []
        self.running = False
        self.packet_id = 1
        self.create_widgets()
        self.supported_tags = {
            "TCP", "UDP", "ICMP", "IGMP", "ARP",
            "GRE", "ESP", "AH", "OSPF", "EtherType 0x86dd"
        }
    def create_widgets(self):

        # === Title ===
        title = tk.Label(self, text="KU NetCap - Live Packet Capture", font=("Arial", 20, "bold"), bg="aqua")
        title.pack(pady=10)

        # === Top Controls Frame ===
        top_frame = tk.Frame(self, bg="aqua")
        top_frame.pack(fill="x", pady=5)
        tk.Label(top_frame, text="Available Interfaces:", bg="aqua").grid(row=0, column=0, padx=5, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(top_frame, textvariable=self.interface_var, state="readonly", width=35)
        self.interface_dropdown['values'] = get_interfaces()
        self.interface_dropdown.current(0)
        self.interface_dropdown.grid(row=1, column=0, padx=5, pady=2)

        tk.Label(top_frame, text="Enter Specific IP or leave blank to capture all:", bg="aqua").grid(
            row=0, column=1, padx=5, sticky="w")

        self.ip_entry = tk.Entry(top_frame, width=35)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=2)
        self.start_btn = tk.Button(top_frame, text="Start", bg="green", fg="white", command=self.start_capture)
        self.start_btn.grid(row=1, column=2, padx=10)
        self.stop_btn = tk.Button(top_frame, text="Stop", bg="red", fg="white", command=self.stop_capture,
                                  state="disabled")
        self.stop_btn.grid(row=1, column=3, padx=10)

        # === Filter Frame (Below headers) ===
        filter_frame = tk.Frame(self, bg="aqua")
        filter_frame.pack(fill="x", pady=2)
        tk.Label(filter_frame, text="Filter by Protocol:", bg="aqua").pack(side="left", padx=(15, 5))
        self.filter_var = tk.StringVar(value="All")
        self.protocol_filter = ttk.Combobox(filter_frame, textvariable=self.filter_var, state="readonly", width=20)
        self.protocol_filter['values'] = ["All", "TCP", "UDP", "ICMP", "IGMP", "ARP", "OSPF", "GRE", "ESP", "AH",
                                          "EtherType 0x86dd"]
        self.protocol_filter.current(0)
        self.protocol_filter.pack(side="left")
        self.protocol_filter.bind("<<ComboboxSelected>>", lambda e: self.filter_packets())

        # === Table Frame with Working Scrollbars ===
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical")
        hsb = ttk.Scrollbar(table_frame, orient="horizontal")

        # Treeview
        self.packet_table = ttk.Treeview(
            table_frame,
            columns=("ID", "Time", "Source", "Destination", "Proto", "Size", "Info"),
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )

        # Attach scrollbars
        vsb.config(command=self.packet_table.yview)
        hsb.config(command=self.packet_table.xview)

        # Use grid instead of pack to ensure proper layout
        self.packet_table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Column widths (set wide to guarantee horizontal scroll)
        self.packet_table.column("ID", width=60, anchor="center", stretch=False)
        self.packet_table.column("Time", width=140, anchor="center", stretch=False)
        self.packet_table.column("Source", width=300, anchor="center", stretch=False)
        self.packet_table.column("Destination", width=300, anchor="center", stretch=False)
        self.packet_table.column("Proto", width=100, anchor="center", stretch=False)
        self.packet_table.column("Size", width=80, anchor="center", stretch=False)
        self.packet_table.column("Info", width=1000, anchor="center", stretch=False)
        for col in self.packet_table["columns"]:
            self.packet_table.heading(col, text=col)
        self.packet_table.bind("<<TreeviewSelect>>", self.display_packet_details)

        # === Protocol Color Tags ===
        tag_colors = {
            "TCP": "#ccffcc",  # light green
            "UDP": "#cce5ff",  # light blue
            "ICMP": "#fff8b3",  # light yellow
            "ARP": "#ffd9b3",  # light orange
            "IGMP": "#f0d9ff",  # light lavender
            "GRE": "#ffe6e6",  # soft pink
            "ESP": "#e6f2ff",  # icy blue
            "AH": "#f9e0ff",  # light purple
            "OSPF": "#f5ffe6",  # pale lime
            "EtherType 0x86dd": "#e6e6ff",  # IPv6 purple-gray
            "Unknown": "#e0e0e0"  # neutral gray
        }
        for proto, color in tag_colors.items():
            self.packet_table.tag_configure(proto, background=color)

        # === Bottom Frame (Protocol Tree + Hex/ASCII View Combined) ===
        bottom_frame = tk.PanedWindow(self, orient="horizontal", sashrelief="raised", bg="aqua")
        bottom_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Packet Structure Tree (Protocol Tree)
        self.protocol_tree = ttk.Treeview(bottom_frame)
        self.protocol_tree.bind("<<TreeviewSelect>>", self.on_protocol_select)
        bottom_frame.add(self.protocol_tree)

        # Combined Hex + ASCII View
        self.payload_text = tk.Text(bottom_frame, height=10, width=80, font=("Courier", 9))
        bottom_frame.add(self.payload_text)

        # Right-click context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_selected)
        self.context_menu.add_command(label="Clear", command=self.clear_table)
        self.context_menu.add_command(label="Save As", command=self.save_as_pcap)
        self.context_menu.add_command(label="Open PCAP...", command=self.open_pcap)

        # Bind right-click to table and hex view
        self.packet_table.bind("<Button-3>", self.show_context_menu)
        self.payload_text.bind("<Button-3>", self.show_context_menu)

    # --- Capture Lifecycle ---
    def start_capture(self):
        self.running = True
        self.packet_id = 1
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.interface_dropdown.config(state="disabled")
        self.ip_entry.config(state="disabled")
        self.packet_table.delete(*self.packet_table.get_children())
        self.packets.clear()
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_capture(self):
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.interface_dropdown.config(state="readonly")
        self.ip_entry.config(state="normal")

    def sniff_packets(self):
        selected = self.interface_var.get().split(" - ")[0]
        target_ip = self.ip_entry.get().strip()

        def process(packet):
            if not self.running:
                return False
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                if target_ip and target_ip not in [src, dst]:
                    return
            self.after(0, self.add_packet, packet)

        sniff(
            iface=selected,
            prn=process,
            store=False,
            stop_filter=lambda x: not self.running
        )

    # --- Packet Handling ---
    def add_packet(self, packet):
        size = len(packet)
        pkt_time = time.strftime("%H:%M:%S", time.localtime(packet.time))
        src = dst = proto = "Unknown"
        info = ""

        if IP in packet:
            ip = packet[IP]
            src = ip.src
            dst = ip.dst
            proto_num = ip.proto
            proto = protocol_map.get(proto_num, f"Proto-{proto_num}")

        elif IPv6 in packet:
            ip6 = packet[IPv6]
            src = ip6.src
            dst = ip6.dst
            proto_num = ip6.nh
            proto = protocol_map.get(proto_num, f"Proto-{proto_num}")
            proto = "EtherType 0x86dd"

        elif ARP in packet:
            if Ether in packet:
                eth = packet[Ether]
                src = eth.src
                dst = eth.dst
            proto = "ARP"

        elif Ether in packet:
            eth = packet[Ether]
            src = eth.src
            dst = eth.dst
            ether_type = eth.type
            proto = f"EtherType {hex(ether_type)}"
            known_ethertypes = {0x0800, 0x0806, 0x86dd, 0x88cc, 0x8100}
            if ether_type not in known_ethertypes:
                return
        else:
            return

        info = get_info(packet)
        if "Unknown or Unsupported Protocol" in info or "Error parsing" in info:
            return

        info = info[:97] + "..." if len(info) > 100 else info
        row = (self.packet_id, pkt_time, src, dst, proto, size, info)
        tag = proto if proto in self.supported_tags else "Unknown"

        self.packet_table.insert("", "end", values=row, tags=(tag,))
        self.packets.append((packet, row, tag))  # ⬅ Store with tag
        self.packet_id += 1

    def filter_packets(self):
        selected_proto = self.filter_var.get()
        self.packet_table.delete(*self.packet_table.get_children())

        for packet, row, tag in self.packets:
            if selected_proto == "All" or row[4] == selected_proto:
                self.packet_table.insert("", "end", values=row, tags=(tag,))

    def display_packet_details(self, event):
        selected = self.packet_table.selection()
        if not selected:
            return

        row = self.packet_table.item(selected[0])["values"]
        if not row:
            return
        packet_id = row[0]

        # Find the actual packet object from self.packets
        packet = next((pkt for pkt, r, _ in self.packets if r[0] == packet_id), None)
        if not packet:
            return

        self.selected_packet = packet
        self.protocol_tree.delete(*self.protocol_tree.get_children())
        self.protocol_offsets = {}
        offset = 0

        try:
            raw_bytes = raw(packet)
        except Exception as e:
            print(f"[Warning] Could not extract raw bytes: {e}")
            return

        total_len = len(raw_bytes)
        frame_id = self.protocol_tree.insert("", "end", text=f"Frame: {total_len} bytes")
        self.protocol_offsets[frame_id] = (0, total_len)

        # === Ethernet Layer ===
        if Ether in packet:
            eth = packet[Ether]
            eth_id = self.protocol_tree.insert("", "end", text="Ethernet II")
            dst_mac = eth.dst.upper()
            src_mac = eth.src.upper()
            eth_type = eth.type

            dst_mac_id = self.protocol_tree.insert(eth_id, "end", text=f"Destination: {dst_mac}")
            src_mac_id = self.protocol_tree.insert(eth_id, "end", text=f"Source: {src_mac}")
            type_id = self.protocol_tree.insert(eth_id, "end", text=f"Type: 0x{eth_type:04x}")

            self.protocol_offsets[eth_id] = (0, 14)
            self.protocol_offsets[dst_mac_id] = (0, 6)
            self.protocol_offsets[src_mac_id] = (6, 12)
            self.protocol_offsets[type_id] = (12, 14)
            offset = 14

        # === IPv4 Layer ===
        if IP in packet:
            ip = packet[IP]
            ip_id = self.protocol_tree.insert("", "end", text="IPv4")
            self.protocol_offsets[ip_id] = (offset, offset + ip.ihl * 4)

            version_ihl = self.protocol_tree.insert(ip_id, "end", text=f"Version: {ip.version}, IHL: {ip.ihl}")
            tos_id = self.protocol_tree.insert(ip_id, "end", text=f"TOS: {ip.tos}")
            len_id = self.protocol_tree.insert(ip_id, "end", text=f"Length: {ip.len}")
            id_id = self.protocol_tree.insert(ip_id, "end", text=f"ID: {ip.id}")
            flags_id = self.protocol_tree.insert(ip_id, "end", text=f"Flags: {ip.flags}")
            ttl_id = self.protocol_tree.insert(ip_id, "end", text=f"TTL: {ip.ttl}")
            proto_id = self.protocol_tree.insert(ip_id, "end", text=f"Protocol: {ip.proto}")
            chksum_id = self.protocol_tree.insert(ip_id, "end", text=f"Checksum: 0x{ip.chksum:04x}")
            src_id = self.protocol_tree.insert(ip_id, "end", text=f"Source IP: {ip.src}")
            dst_id = self.protocol_tree.insert(ip_id, "end", text=f"Destination IP: {ip.dst}")

            # Approximate offsets inside IP header
            ip_base = offset
            self.protocol_offsets[version_ihl] = (ip_base, ip_base + 1)
            self.protocol_offsets[tos_id] = (ip_base + 1, ip_base + 2)
            self.protocol_offsets[len_id] = (ip_base + 2, ip_base + 4)
            self.protocol_offsets[id_id] = (ip_base + 4, ip_base + 6)
            self.protocol_offsets[flags_id] = (ip_base + 6, ip_base + 8)
            self.protocol_offsets[ttl_id] = (ip_base + 8, ip_base + 9)
            self.protocol_offsets[proto_id] = (ip_base + 9, ip_base + 10)
            self.protocol_offsets[chksum_id] = (ip_base + 10, ip_base + 12)
            self.protocol_offsets[src_id] = (ip_base + 12, ip_base + 16)
            self.protocol_offsets[dst_id] = (ip_base + 16, ip_base + 20)
            offset += ip.ihl * 4


        # === TCP/UDP Detailed Header ===
        if TCP in packet or UDP in packet:
            layer = packet[TCP] if TCP in packet else packet[UDP]
            proto_name = "TCP" if TCP in packet else "UDP"
            proto_id = self.protocol_tree.insert("", "end", text=f"Protocol: {proto_name}")
            start = offset  # Save for offsets

            if proto_name == "TCP":
                self.protocol_tree.insert(proto_id, "end", text=f"Src Port: {layer.sport}")
                self.protocol_tree.insert(proto_id, "end", text=f"Dst Port: {layer.dport}")
                self.protocol_tree.insert(proto_id, "end", text=f"Seq: {layer.seq}")
                self.protocol_tree.insert(proto_id, "end", text=f"Ack: {layer.ack}")
                self.protocol_tree.insert(proto_id, "end", text=f"Data Offset: {layer.dataofs}")
                self.protocol_tree.insert(proto_id, "end", text=f"Flags: {layer.flags}")
                self.protocol_tree.insert(proto_id, "end", text=f"Window: {layer.window}")
                self.protocol_tree.insert(proto_id, "end", text=f"Checksum: 0x{layer.chksum:04x}")
                self.protocol_tree.insert(proto_id, "end", text=f"Urgent Pointer: {layer.urgptr}")

                self.protocol_offsets[proto_id] = (start, start + 20)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[0]] = (start, start + 2)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[1]] = (start + 2, start + 4)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[2]] = (start + 4, start + 8)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[3]] = (start + 8, start + 12)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[4]] = (start + 12, start + 13)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[5]] = (start + 13, start + 14)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[6]] = (start + 14, start + 16)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[7]] = (start + 16, start + 18)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[8]] = (start + 18, start + 20)
                offset += 20

            else:  # UDP
                self.protocol_tree.insert(proto_id, "end", text=f"Src Port: {layer.sport}")
                self.protocol_tree.insert(proto_id, "end", text=f"Dst Port: {layer.dport}")
                self.protocol_tree.insert(proto_id, "end", text=f"Length: {layer.len}")
                self.protocol_tree.insert(proto_id, "end", text=f"Checksum: 0x{layer.chksum:04x}")

                self.protocol_offsets[proto_id] = (start, start + 8)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[0]] = (start, start + 2)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[1]] = (start + 2, start + 4)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[2]] = (start + 4, start + 6)
                self.protocol_offsets[self.protocol_tree.get_children(proto_id)[3]] = (start + 6, start + 8)
                offset += 8

        # === ICMP ===
        if ICMP in packet:
            icmp = packet[ICMP]
            icmp_id = self.protocol_tree.insert("", "end", text="ICMP")
            type_id = self.protocol_tree.insert(icmp_id, "end", text=f"Type: {icmp.type}")
            code_id = self.protocol_tree.insert(icmp_id, "end", text=f"Code: {icmp.code}")
            chksum_id = self.protocol_tree.insert(icmp_id, "end", text=f"Checksum: 0x{icmp.chksum:04x}")
            self.protocol_offsets[icmp_id] = (offset, offset + 8)
            self.protocol_offsets[type_id] = (offset, offset + 1)
            self.protocol_offsets[code_id] = (offset + 1, offset + 2)
            self.protocol_offsets[chksum_id] = (offset + 2, offset + 4)
            offset += len(icmp)

        # === IGMP ===
        if hasattr(packet, "proto") and packet.proto == 2:
            igmp_id = self.protocol_tree.insert("", "end", text="IGMP")
            self.protocol_tree.insert(igmp_id, "end", text="IGMP Packet (Not Deep Parsed)")
            self.protocol_offsets[igmp_id] = (offset, offset + 8)
            offset += 8

        # === OSPF ===
        if hasattr(packet, "proto") and packet.proto == 89:
            ospf_id = self.protocol_tree.insert("", "end", text="OSPF")
            self.protocol_tree.insert(ospf_id, "end", text="OSPF Packet (Not Deep Parsed)")
            self.protocol_offsets[ospf_id] = (offset, offset + 24)
            offset += 24

        # === GRE ===
        if hasattr(packet, "proto") and packet.proto == 47:
            gre_id = self.protocol_tree.insert("", "end", text="GRE")
            self.protocol_tree.insert(gre_id, "end", text="GRE Header (not deeply parsed)")
            # GRE header is typically 4 or more bytes
            self.protocol_offsets[gre_id] = (offset, offset + 4)
            offset += 4

        # === ESP ===
        if hasattr(packet, "proto") and packet.proto == 50:
            esp_id = self.protocol_tree.insert("", "end", text="ESP (Encrypted)")
            spi_id = self.protocol_tree.insert(esp_id, "end", text="SPI (Security Parameters Index)")
            seq_id = self.protocol_tree.insert(esp_id, "end", text="Sequence Number")

            self.protocol_offsets[esp_id] = (offset, offset + 8)
            self.protocol_offsets[spi_id] = (offset, offset + 4)
            self.protocol_offsets[seq_id] = (offset + 4, offset + 8)
            offset += 8  # ESP payload length is unknown due to encryption

        # === AH ===
        if hasattr(packet, "proto") and packet.proto == 51:
            ah_id = self.protocol_tree.insert("", "end", text="AH (Authentication Header)")
            spi_id = self.protocol_tree.insert(ah_id, "end", text="SPI")
            seq_id = self.protocol_tree.insert(ah_id, "end", text="Sequence Number")

            self.protocol_offsets[ah_id] = (offset, offset + 12)
            self.protocol_offsets[spi_id] = (offset, offset + 4)
            self.protocol_offsets[seq_id] = (offset + 4, offset + 8)
            offset += 12

        # === ARP Layer ===
        if ARP in packet:
            arp = packet[ARP]
            arp_id = self.protocol_tree.insert("", "end", text="ARP")

            hw_type_id = self.protocol_tree.insert(arp_id, "end", text=f"Hardware Type: {arp.hwtype}")
            proto_type_id = self.protocol_tree.insert(arp_id, "end", text=f"Protocol Type: 0x{arp.ptype:04x}")
            hw_len_id = self.protocol_tree.insert(arp_id, "end", text=f"Hardware Size: {arp.hwlen}")
            proto_len_id = self.protocol_tree.insert(arp_id, "end", text=f"Protocol Size: {arp.plen}")
            op_id = self.protocol_tree.insert(arp_id, "end", text=f"Opcode: {arp.op}")
            sender_mac_id = self.protocol_tree.insert(arp_id, "end", text=f"Sender MAC: {arp.hwsrc}")
            sender_ip_id = self.protocol_tree.insert(arp_id, "end", text=f"Sender IP: {arp.psrc}")
            target_mac_id = self.protocol_tree.insert(arp_id, "end", text=f"Target MAC: {arp.hwdst}")
            target_ip_id = self.protocol_tree.insert(arp_id, "end", text=f"Target IP: {arp.pdst}")

            self.protocol_offsets[arp_id] = (offset, offset + 28)
            self.protocol_offsets[hw_type_id] = (offset, offset + 2)
            self.protocol_offsets[proto_type_id] = (offset + 2, offset + 4)
            self.protocol_offsets[hw_len_id] = (offset + 4, offset + 5)
            self.protocol_offsets[proto_len_id] = (offset + 5, offset + 6)
            self.protocol_offsets[op_id] = (offset + 6, offset + 8)
            self.protocol_offsets[sender_mac_id] = (offset + 8, offset + 14)
            self.protocol_offsets[sender_ip_id] = (offset + 14, offset + 18)
            self.protocol_offsets[target_mac_id] = (offset + 18, offset + 24)
            self.protocol_offsets[target_ip_id] = (offset + 24, offset + 28)
            offset += 28

        # === IPv6 ===
        if IPv6 in packet:
            ip6 = packet[IPv6]
            ip6_id = self.protocol_tree.insert("", "end", text="IPv6")

            ver_tc_fl = self.protocol_tree.insert(ip6_id, "end", text=f"Version: {ip6.version}")
            tc_id = self.protocol_tree.insert(ip6_id, "end", text=f"Traffic Class: {ip6.tc}")
            flow_id = self.protocol_tree.insert(ip6_id, "end", text=f"Flow Label: {ip6.fl}")
            plen_id = self.protocol_tree.insert(ip6_id, "end", text=f"Payload Length: {ip6.plen}")
            nh_id = self.protocol_tree.insert(ip6_id, "end", text=f"Next Header: {ip6.nh}")
            hlim_id = self.protocol_tree.insert(ip6_id, "end", text=f"Hop Limit: {ip6.hlim}")
            src6_id = self.protocol_tree.insert(ip6_id, "end", text=f"Source IPv6: {ip6.src}")
            dst6_id = self.protocol_tree.insert(ip6_id, "end", text=f"Destination IPv6: {ip6.dst}")

            self.protocol_offsets[ip6_id] = (offset, offset + 40)
            self.protocol_offsets[ver_tc_fl] = (offset, offset + 4)
            self.protocol_offsets[tc_id] = (offset, offset + 1)
            self.protocol_offsets[flow_id] = (offset + 1, offset + 4)
            self.protocol_offsets[plen_id] = (offset + 4, offset + 6)
            self.protocol_offsets[nh_id] = (offset + 6, offset + 7)
            self.protocol_offsets[hlim_id] = (offset + 7, offset + 8)
            self.protocol_offsets[src6_id] = (offset + 8, offset + 24)
            self.protocol_offsets[dst6_id] = (offset + 24, offset + 40)
            offset += 40

        # === Other Layer 2 (LLDP/STP/etc.)
        if Ether in packet:
            ether_type = packet[Ether].type
            if ether_type in [0x88cc, 0x8100, 0x8847]:
                other_id = self.protocol_tree.insert("", "end", text=f"EtherType 0x{ether_type:04x}")
                self.protocol_tree.insert(other_id, "end", text="L2 Protocol (not parsed)")
                self.protocol_offsets[other_id] = (offset, offset + 20)
                offset += 20

        # === Payload ===
        if Raw in packet:
            raw_layer = packet[Raw]
            payload = bytes(raw_layer)
            payload_id = self.protocol_tree.insert("", "end", text="Payload")
            self.protocol_offsets[payload_id] = (offset, offset + len(payload))

        # === Hex & ASCII View ===
        self.payload_text.delete("1.0", "end")
        for i in range(0, len(raw_bytes), 16):
            line = raw_bytes[i:i + 16]
            hex_part = ' '.join(f"{b:02x}" for b in line)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line)
            addr = f"{i:04x}"
            hex_line = f"{addr}  {hex_part}"
            ascii_line = f"{addr}  {hex_part.ljust(48)}  {ascii_part}"
            self.payload_text.insert("end", ascii_line + "\n")

    def render_hex_views(self, raw_bytes):
        self.payload_text.delete("1.0", tk.END)
        for i in range(0, len(raw_bytes), 16):
            line = raw_bytes[i:i + 16]
            hex_part = ' '.join(f"{b:02x}" for b in line)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line)
            addr = f"{i:04x}"
            ascii_line = f"{addr}  {hex_part.ljust(48)}  {ascii_part}"
            self.payload_text.insert(tk.END, ascii_line + "\n")

    def on_protocol_select(self, event):
        selected_item = self.protocol_tree.selection()
        if not selected_item:
            return
        item_id = selected_item[0]
        if item_id not in self.protocol_offsets:
            return
        start, end = self.protocol_offsets[item_id]
        self.payload_text.tag_remove("highlight", "1.0", "end")

        for i in range(start, end):
            line = i // 16 + 1
            col = i % 16 * 3 + 6
            self.payload_text.tag_add("highlight", f"{line}.{col}", f"{line}.{col + 2}")
        self.payload_text.tag_configure("highlight", background="yellow")

    # === Context Menu Logic ===
    def show_context_menu(self, event):
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def copy_selected(self):
        try:
            focus_widget = self.focus_get()
            if focus_widget == self.payload_text:
                selected = self.payload_text.selection_get()
            else:
                selected = self.packet_table.item(self.packet_table.selection()[0])["values"]
                selected = "\t".join(map(str, selected))
            self.clipboard_clear()
            self.clipboard_append(selected)
        except Exception as e:
            messagebox.showerror("Copy Failed", str(e))

    def save_as_pcap(self):
        if not self.packets:
            messagebox.showwarning("No Packets", "There are no packets to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if not path:
            return
        try:
            writer = PcapWriter(path, append=False, sync=True)
            for pkt, *_ in self.packets:
                writer.write(pkt)
            writer.close()
            messagebox.showinfo("Saved", f"Packets saved to {path}")
        except Exception as e:
            messagebox.showerror("Error Saving", str(e))

    def on_close(self):
        if self.packets:
            result = messagebox.askyesnocancel("Exit", "Do you want to quit without saving?")
            if result is None:
                return  # Cancel closing
            elif not result:
                self.save_as_pcap()
        self.winfo_toplevel().destroy()

    def clear_table(self):
        if self.packets:
            result = messagebox.askyesnocancel("Clear", "Do you want to clear without saving?")
            if result is None:
                return  # Cancel clear
            elif not result:
                self.save_as_pcap()

        self.packet_table.delete(*self.packet_table.get_children())
        self.packets.clear()
        self.packet_id = 1
        self.protocol_tree.delete(*self.protocol_tree.get_children())
        self.payload_text.delete("1.0", "end")

    def open_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        if not file_path:
            return

        try:
            packets = rdpcap(file_path)
            for pkt in packets:
                # Fix for EDecimal packet.time
                try:
                    pkt.time = float(pkt.time)
                except Exception:
                    continue  # Skip malformed timestamped packets

                self.add_packet(pkt)
            messagebox.showinfo("✅ Loaded", f"Loaded {len(packets)} packets from:\n{file_path}")
        except Exception as e:
            messagebox.showerror("❌ Error", f"Failed to load PCAP file:\n{e}")

        def on_close(self):
            if self.packets:
                result = messagebox.askyesnocancel("Exit", "Do you want to quit without saving?")
                if result is None:
                    return  # Cancel close
                elif not result:
                    self.save_as_pcap()
            self.winfo_toplevel().destroy()