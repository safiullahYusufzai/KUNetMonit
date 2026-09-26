import tkinter as tk
import threading
import random
import psutil
import socket
import ipaddress
import time
import sys
import os
import scapy.all as scapy  # for when we call scapy.sniff(...)
from scapy.all import ARP, Ether, srp, sniff
from tkinter import ttk
from PIL import Image, ImageTk

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)


class NetworkMonitoringGUI(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="aqua")

        # === Attributes ===
        self.clients = {}
        self.monitoring = False
        self.monitoring_active = False
        self.device_bandwidth = {}
        self.bandwidth_lock = threading.Lock()

        # === Top Controls (STATIC, not inside canvas) ===
        top_frame = tk.Frame(self, bg="aqua")
        top_frame.pack(padx=10, pady=10, anchor="nw", fill="x")

        tk.Label(top_frame, text="Available Networks:", bg="aqua", font=("Arial", 10, "bold")).pack(side="left")

        self.network_var = tk.StringVar()
        self.network_menu = ttk.Combobox(top_frame, textvariable=self.network_var, state="readonly", width=40)
        self.network_menu.pack(side="left", padx=10)
        self.network_menu.bind("<<ComboboxSelected>>", lambda e: self.update_network_ip())
        self.load_networks()

        self.start_btn = tk.Button(top_frame, text="Start", bg="green", fg="white", command=self.start_monitoring)
        self.stop_btn = tk.Button(top_frame, text="Stop", bg="red", fg="white", command=self.stop_monitoring)
        self.start_btn.pack(side="left", padx=10)
        self.stop_btn.pack_forget()

        # === Client Table ===
        self.setup_client_table()

        # === Scrollable Canvas Layout (everything below dropdown) ===
        self.canvas = tk.Canvas(self, bg="aqua", highlightthickness=0)
        self.v_scroll = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.v_scroll.set)

        self.v_scroll.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.content_frame = tk.Frame(self.canvas, bg="aqua")
        self.content_window = self.canvas.create_window((0, 0), window=self.content_frame, anchor="nw")

        self.content_frame.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_resize)

        # Enable mouse wheel scroll on canvas only when hovered
        self.bind_mouse_wheel()



        # === Load Icons ===
        self.load_icons()

        # === Centered Layout for Network + Clients ===
        self.center_frame = tk.Frame(self.content_frame, bg="aqua")
        self.center_frame.pack(fill="both", expand=True)

        self.network_frame = tk.Frame(self.center_frame, bg="aqua")
        self.network_frame.pack(pady=20)

        self.icon_frame = tk.Frame(self.center_frame, bg="aqua")
        self.icon_frame.pack(pady=10)

    def _on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    def _on_canvas_resize(self, event):
        self.canvas.itemconfig(self.content_window, width=event.width)
    def bind_mouse_wheel(self):
        # Windows
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        # Linux
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)
    def _on_mousewheel(self, event):
        if event.num == 4:  # Linux scroll up
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:  # Linux scroll down
            self.canvas.yview_scroll(1, "units")
        else:  # Windows
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def load_icons(self):
        client_img_path = resource_path("computer.png")
        network_img_path = resource_path("network.png")

        self.client_img = ImageTk.PhotoImage(Image.open(client_img_path).resize((60, 60)))
        self.network_img = ImageTk.PhotoImage(Image.open(network_img_path).resize((80, 80)))

    def setup_client_table(self):
        self.table_frame = tk.Frame(self, bg="white")  # ✅ NEW: attach directly to root layout
        self.table_frame.pack(fill="x", padx=10, pady=(5, 10))

        self.client_table = ttk.Treeview(
            self.table_frame,
            columns=("Client", "Ports"),
            show="headings",
            height=5
        )
        self.client_table.heading("Client", text="Client (IP)")
        self.client_table.heading("Ports", text="Open Ports")

        self.client_table.column("Client", width=300, stretch=False)
        self.client_table.column("Ports", width=1400, stretch=False)

        vsb = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.client_table.yview)
        hsb = ttk.Scrollbar(self.table_frame, orient="horizontal", command=self.client_table.xview)

        self.client_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.client_table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)



    def get_available_networks(self):
        networks = []
        for iface, addresses in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(iface)
            if stats and stats.isup:
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        netmask = addr.netmask
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            networks.append((iface, str(ip), str(network)))
                        except Exception:
                            continue
        if not networks:
            raise RuntimeError("❌ No active networks found.")
        return networks
    def load_networks(self):
        """Populate the network dropdown with active interfaces using real scanning logic."""
        networks = ["Select Network"]
        try:
            for iface, net_ip, subnet in self.get_available_networks():
                networks.append(f"{iface} - {net_ip}")
            self.network_menu['values'] = networks
            self.network_menu.current(0)
        except Exception as e:
            networks.append(f"Error: {str(e)}")
            self.network_menu['values'] = networks
            self.network_menu.current(0)
    def update_network_ip(self):
        if self.monitoring:
            self.draw_layout()
    def draw_layout(self):
        for widget in self.icon_frame.winfo_children():
            widget.destroy()
        for widget in self.network_frame.winfo_children():
            widget.destroy()

        self.clients.clear()
        self.client_table.delete(*self.client_table.get_children())

        selected = self.network_var.get()
        subnet = None
        iface = None

        for _iface, _ip, _subnet in self.get_available_networks():
            if f"{_iface} - {_ip}" == selected:
                iface = _iface
                subnet = _subnet
                break

        if not iface or not subnet:
            print("⚠️ Selected network not found.")
            return

        network_icon = tk.Label(self.network_frame, image=self.network_img, bg="aqua")
        network_icon.pack()
        network_label = tk.Label(self.network_frame, text=f"Network\n{subnet}", bg="aqua", font=("Arial", 10, "bold"))


        network_label.pack()

        # Start scanning thread
        threading.Thread(target=self.scan_network, args=(subnet, iface), daemon=True).start()

    def scan_network(self, subnet, iface):
        import scapy.all as scapy
        from scapy.layers.l2 import ARP, Ether

        known_devices = {}
        while self.monitoring_active:
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            try:
                result = scapy.srp(packet, timeout=1, verbose=0, iface=iface)[0]
            except Exception as e:
                print(f"Error during ARP scan: {e}")
                result = []

            new_clients = []
            for sent, received in result:
                mac = received.hwsrc
                ip = received.psrc

                if mac not in known_devices:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = "Unknown"

                    ports = self.scan_ports(ip)

                    known_devices[mac] = {
                        'ip': ip,
                        'mac': mac,
                        'name': hostname,
                        'ports': ports
                    }
                    new_clients.append(known_devices[mac])

            if new_clients:
                self.after(0, self.add_clients_to_gui, new_clients)

            time.sleep(2)  # slow down polling a bit
    def scan_ports(self, ip, ports=None):
        if ports is None:
            ports = [
                21, 22, 23, 25, 53, 80, 110, 123, 135, 139,
                143, 161, 443, 445, 3306, 3389, 8080
            ]

        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        try:
                            name = socket.getservbyport(port, 'tcp').upper()
                        except:
                            name = 'UNKNOWN'
                        open_ports.append(f"{name} ({port})")
            except:
                continue
        return open_ports

    def is_internet_ip(self, ip):
        try:
            if not ip or not isinstance(ip, str):
                return False

            # Common invalid/routing-related IPs
            if ip in {"0.0.0.0", "255.255.255.255"}:
                return False

            if ip.endswith(".255"):
                return False  # Subnet broadcast

            ip_obj = ipaddress.ip_address(ip)

            return not (
                    ip_obj.is_private or
                    ip_obj.is_loopback or
                    ip_obj.is_link_local or
                    ip_obj.is_multicast or
                    ip_obj.is_reserved
            )
        except ValueError:
            return False

    def track_bandwidth(self, packet):
        from scapy.layers.l2 import Ether
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            size = len(packet)

            src_ip = packet[0][1].src if hasattr(packet[0][1], 'src') else None
            dst_ip = packet[0][1].dst if hasattr(packet[0][1], 'dst') else None

            if not (self.is_internet_ip(src_ip) or self.is_internet_ip(dst_ip)):
                return

            with self.bandwidth_lock:
                for mac in [mac_src, mac_dst]:
                    if mac not in self.device_bandwidth:
                        self.device_bandwidth[mac] = {'sent': 0, 'recv': 0}

                self.device_bandwidth[mac_src]['sent'] += size * 8
                self.device_bandwidth[mac_dst]['recv'] += size * 8


    def start_sniffing(self, iface):
        import scapy.all as scapy
        scapy.sniff(iface=iface, prn=self.track_bandwidth, store=False)


    def update_bandwidth_loop(self):
        while self.monitoring_active:
            with self.bandwidth_lock:
                for mac, label_info in self.clients.items():
                    label = label_info["label"]
                    if mac in self.device_bandwidth:
                        sent = self.device_bandwidth[mac]["sent"] / 1_000_000
                        recv = self.device_bandwidth[mac]["recv"] / 1_000_000
                    else:
                        sent = recv = 0.0

                    # Reset values for next interval
                    self.device_bandwidth[mac] = {'sent': 0, 'recv': 0}

                    try:
                        current_text = label.cget("text")
                        lines = current_text.split("\n")
                        lines[-2] = f"Sent: {sent:.2f} Mbps"
                        lines[-1] = f"Recv: {recv:.2f} Mbps"
                        label.config(text="\n".join(lines))
                    except Exception:
                        continue
            time.sleep(1)

    def add_clients_to_gui(self, new_clients):
        for idx, device in enumerate(new_clients, start=len(self.clients) + 1):
            row_frame = tk.Frame(self.icon_frame, bg="aqua")
            row_frame.grid(row=(idx - 1) // 5, column=(idx - 1) % 5, padx=10, pady=5)

            icon = tk.Label(row_frame, image=self.client_img, bg="aqua")
            icon.pack()

            info = (f"ID: {idx}\n"
                    f"Name: {device['name']}\n"
                    f"MAC: {device['mac']}\n"
                    f"IP: {device['ip']}\n"
                    f"Sent: 0.00 Mbps\n"
                    f"Recv: 0.00 Mbps")
            label = tk.Label(row_frame, text=info, bg="aqua", font=("Arial", 8), justify="center")
            label.pack()

            self.clients[device['mac']] = {"label": label}

            self.client_table.insert("", "end", values=(device['ip'], ", ".join(device['ports'])))





    def start_monitoring(self):
        if self.monitoring or self.monitoring_active:
            return  # Already running

        selected = self.network_var.get()
        if " - " not in selected or selected == "Select Network":
            print("❌ No network selected.")
            return

        self.monitoring = True
        self.monitoring_active = True

        self.start_btn.pack_forget()
        self.stop_btn.pack(side="left", padx=10)
        self.network_menu.config(state="disabled")

        self.draw_layout()

        iface = selected.split(" - ")[0]
        threading.Thread(target=self.start_sniffing, args=(iface,), daemon=True).start()
        threading.Thread(target=self.update_bandwidth_loop, daemon=True).start()

    def stop_monitoring(self):
        if not self.monitoring:
            return

        self.monitoring = False
        self.monitoring_active = False

        self.stop_btn.pack_forget()
        self.start_btn.pack(side="left", padx=10)
        self.network_menu.config(state="readonly")

        for widget in self.icon_frame.winfo_children():
            widget.destroy()
        for widget in self.network_frame.winfo_children():
            widget.destroy()

        self.clients.clear()
        self.client_table.delete(*self.client_table.get_children())