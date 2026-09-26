import tkinter as tk
import os
import sys
from KUNetCapGUI import KUNetCapGUI
from NetworkMonitoringGUI import NetworkMonitoringGUI
from SplashScreen import SplashScreen


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("KU NetMonit")
        self.geometry("900x600")
        self.configure(bg="white")

        self.sidebar_expanded = True
        self.sidebar_width_expanded = 200
        self.sidebar_width_collapsed = 50

        self.create_sidebar()
        self.create_main_content()

        # Create embedded views
        self.network_monitor_view = NetworkMonitoringGUI(self.main_frame)
        self.network_monitor_view.place(relwidth=1, relheight=1)
        self.network_monitor_view.lower()

        self.packet_capture_view = KUNetCapGUI(self.main_frame)
        self.packet_capture_view.place(relwidth=1, relheight=1)
        self.packet_capture_view.lower()

        self.protocol("WM_DELETE_WINDOW", self.on_main_close)  # Optional redundancy


        self.show_home()

    def on_main_close(self):
        # Stop monitoring if active
        try:
            if hasattr(self, "network_monitor_view"):
                self.network_monitor_view.monitoring = False
                self.network_monitor_view.monitoring_active = False
        except Exception as e:
            print(f"[Shutdown Hook Error] {e}")

        # Ask to save pcap if packet capture is active
        if hasattr(self, "packet_capture_view") and self.packet_capture_view.packets:
            self.packet_capture_view.on_close()
        else:
            self.destroy()

    def create_sidebar(self):
        self.sidebar = tk.Frame(self, bg="#003366", width=self.sidebar_width_expanded)
        self.sidebar.pack(side="left", fill="y")

        self.toggle_button = tk.Button(
            self.sidebar, text="☰", bg="#003366", fg="white", font=("Segoe UI", 14),
            bd=0, command=self.toggle_sidebar
        )
        self.toggle_button.pack(pady=10, padx=10, anchor="w")

        self.home_button = self.create_menu_button("Home", self.show_home)
        self.netmonit_button = self.create_menu_button("Network Monitoring", lambda: self.show_view("NetworkMonitoring"))
        self.netcap_button = self.create_menu_button("Packet Capturing", lambda: self.show_view("PacketCapturing"))

        self.spacer = tk.Label(self.sidebar, text="", bg="#003366")
        self.spacer.pack(expand=True, fill="both")

        self.about_button = self.create_menu_button("About", self.show_about)
        self.help_button = self.create_menu_button("Help", self.show_help)
        self.help_button = self.create_menu_button("License", self.show_License)

    def create_menu_button(self, text, command):
        btn = tk.Button(
            self.sidebar, text=text, bg="#003366", fg="white", font=("Segoe UI", 12),
            bd=0, anchor="w", command=command
        )
        btn.pack(fill="x", padx=10, pady=5)
        return btn

    def create_main_content(self):
        self.main_frame = tk.Frame(self, bg="white")
        self.main_frame.pack(side="left", fill="both", expand=True)

        self.canvas = tk.Canvas(self.main_frame, bg="white")
        self.canvas.pack(fill="both", expand=True, side="left")

        self.scrollbar_y = tk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollbar_y.pack(side="right", fill="y")

        self.canvas.configure(yscrollcommand=self.scrollbar_y.set)

        self.inner_frame = tk.Frame(self.canvas, bg="white")
        self.canvas_window = self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")

        self.inner_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self.resize_inner_frame)

    def resize_inner_frame(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def clear_main_content(self):
        for widget in self.inner_frame.winfo_children():
            widget.destroy()

    def toggle_sidebar(self):
        if self.sidebar_expanded:
            self.sidebar.config(width=self.sidebar_width_collapsed)
            for widget in self.sidebar.winfo_children():
                if widget != self.toggle_button:
                    widget.pack_forget()
            self.sidebar_expanded = False
        else:
            self.sidebar.config(width=self.sidebar_width_expanded)
            self.toggle_button.pack(pady=10, padx=10, anchor="w")
            self.home_button.pack(fill="x", padx=10, pady=5)
            self.netmonit_button.pack(fill="x", padx=10, pady=5)
            self.netcap_button.pack(fill="x", padx=10, pady=5)
            self.spacer.pack(expand=True, fill="both")
            self.about_button.pack(fill="x", padx=10, pady=5)
            self.help_button.pack(fill="x", padx=10, pady=5)
            self.sidebar_expanded = True

    def show_home(self):
        self.packet_capture_view.lower()
        self.network_monitor_view.lower()
        self.clear_main_content()
        text = """
Name: SAFIULLAH YUSUFZAI
Project: KU NetMonit
Instructor: Assistant Prof. SIBGHATULLAH RAHMATZAI

My name is Safiullah Yusufzai, a final-year Bachelor of Computer Science (BCS)
student with a passion for networking and cybersecurity. I am honored to be 
mentored by Mr. Sibghatullah Rahmatzai, whose guidance has been instrumental 
throughout my academic journey.

My final year project, KU NetMonit, is a comprehensive network monitoring and 
packet capturing system designed for Windows Server environments. It helps 
track real-time bandwidth usage and capture packet-level data for detailed 
inspection similar to tools like Wireshark but tailored for centralized server 
monitoring in local networks.
        """
        label = tk.Label(self.inner_frame, text=text, font=("Segoe UI", 12), bg="white", justify="left", anchor="nw")
        label.pack(pady=20, padx=20, anchor="nw")

    def show_about(self):
        self.packet_capture_view.lower()
        self.network_monitor_view.lower()
        self.clear_main_content()
        text = """
📘 About KU NetMonit:

# KUNetMonit v1.0 - Network Monitoring and Packet Capturing Application
Developed by: Safiullah Yusufzai
Under the mentorship of: Sibghatullah Rahmatzai
Organization: Kabul University

# Features
Monitor network clients, ports, and bandwidth.
Auto-detect connected devices.
Capture the incoming and outgoing packets from the client computers.
Supports network monitoring when deployed on a Windows Server configured as a gateway or on a switch mirror/SPAN port.

#Prerequisites
Before running KUNetMonit, the following is required:
Windows operating system
Npcap required for network packet capture and monitoring.

#Deployment Environment
KUNetMonit is designed to operate in network environments where the monitoring system can receive the relevant network traffic.
It can be deployed in either of the following configurations:
1. Windows Server configured as a network gateway**
   KUNetMonit can monitor network traffic passing through the Windows Server.
2. Switch with a mirrored/SPAN port**
   KUNetMonit can be connected to a switch mirror port configured to provide a copy of the relevant network traffic to the monitoring system.

#Usage
To start, double-click the desktop shortcut.

#Support
For support, contact: **[Safiullahy7@gmail.com](mailto:Safiullahy7@gmail.com)**

#License
Copyright (c) 2026 Safiullah Yusufzai
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for the full license text.

        """
        label = tk.Label(self.inner_frame, text=text, font=("Segoe UI", 12), bg="white", justify="left", anchor="nw")
        label.pack(pady=20, padx=20, anchor="nw")

    def show_help(self):
        self.packet_capture_view.lower()
        self.network_monitor_view.lower()
        self.clear_main_content()
        text = """
🛠️ Help & Requirements:

✅ After installation (EXE version), no Python installation is required.

External Requirements:
- 🧩 **Npcap** (in WinPcap-compatible mode) — Required for capturing packets.
- 🖥️ **Windows Server OS** — Should act as the local gateway to monitor clients.
- 🔀 **Port Mirroring** (SPAN) — For switches to mirror client traffic to server interface.
- 👩‍💻 **Run as Administrator** — To allow low-level packet sniffing and access to interfaces.

Usage Tips:_-

- Use packet highlighting to inspect headers and payload.
- Check open ports and real-time bandwidth usage per client.

Make sure all prerequisites are installed **before** launching the application.
        """
        label = tk.Label(self.inner_frame, text=text, font=("Segoe UI", 12), bg="white", justify="left", anchor="nw")
        label.pack(pady=20, padx=20, anchor="nw")

    def show_License(self):
            self.packet_capture_view.lower()
            self.network_monitor_view.lower()
            self.clear_main_content()
            text = """
📜 License:

MIT License

Copyright (c) 2026 Safiullah Yusufzai

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
            """
            label = tk.Label(self.inner_frame, text=text, font=("Segoe UI", 12), bg="white", justify="left",
                             anchor="nw")
            label.pack(pady=20, padx=20, anchor="nw")

    def show_view(self, view_key):
        self.clear_main_content()
        if view_key == "NetworkMonitoring":
            self.packet_capture_view.lower()
            self.network_monitor_view.lift()
        elif view_key == "PacketCapturing":
            self.network_monitor_view.lower()
            self.packet_capture_view.lift()

if __name__ == "__main__":
    # Create temporary root for splash
    splash_root = tk.Tk()
    splash_root.withdraw()

    splash = SplashScreen(splash_root, resource_path("KUNetmonit.jpg"), duration=5000)
    splash.wait_window()

    # Destroy the splash root completely
    splash_root.destroy()

    # Now start the actual app (single root window)
    app = MainApp()
    app.iconbitmap(resource_path("KUNetmonit.ico"))
    app.mainloop()