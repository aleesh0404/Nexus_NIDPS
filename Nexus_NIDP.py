#!/usr/bin/env python3
# ==============================================================================
# PROJECT: Nexus Network Intrusion Detection & Prevention System with Login
# COURSE: Ethical Hacking and Cyber Security
# MODULE: Secure Software Development
# ==============================================================================
# USAGE: sudo -E python3 app.py
# ==============================================================================

import sys
import time
import threading
import collections
import subprocess
from collections import defaultdict
import os
from tkinter import messagebox

try:
    import customtkinter as ctk
except ImportError:
    print("ERROR: pip install customtkinter")
    sys.exit(1)

try:
    import scapy.all as scapy
except ImportError:
    print("ERROR: pip install scapy")
    sys.exit(1)

# ==============================================================================
# CONSTANTS
# ==============================================================================

USER_FILE = "user.txt"

# ==============================================================================
# 🎨 COLOR SCHEME
# ==============================================================================

class Colors:
    BG_DARK = "#0d1117"
    BG_CARD = "#161b22"
    BG_FRAME = "#21262d"
    PRIMARY = "#58a6ff"
    SUCCESS = "#3fb950"
    WARNING = "#d29922"
    DANGER = "#f85149"
    PURPLE = "#bc8cff"
    TEXT_MAIN = "#f0f6fc"
    TEXT_DIM = "#8b949e"
    TEXT_MUTED = "#484f58"
    BORDER = "#30363d"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ==============================================================================
# LO1: CUSTOM DATA STRUCTURES
# ==============================================================================

class ResultNode:
    def __init__(self, message):
        self.message = message
        self.timestamp = time.strftime("%H:%M:%S")
        self.next = None

class DiscoveryStorage:
    def __init__(self, max_size=1000):
        self.head = None
        self.count = 0
        self.max_size = max_size

    def insert(self, message):
        new_node = ResultNode(message)
        new_node.next = self.head
        self.head = new_node
        self.count += 1
        if self.count > self.max_size:
            self._trim()

    def _trim(self):
        current = self.head
        if current and current.next:
            while current.next.next:
                current = current.next
            current.next = None
            self.count -= 1

    def get_all(self):
        results = []
        current = self.head
        while current:
            results.append(f"[{current.timestamp}] {current.message}")
            current = current.next
        return results

    def clear(self):
        self.head = None
        self.count = 0

class PacketNode:
    def __init__(self, data):
        self.data = data
        self.next = None

class CustomQueue:
    def __init__(self):
        self.head = None
        self.tail = None
        self._lock = threading.Lock()
        self._size = 0

    def enqueue(self, data):
        with self._lock:
            node = PacketNode(data)
            if self.tail is None:
                self.head = self.tail = node
            else:
                self.tail.next = node
                self.tail = node
            self._size += 1

    def dequeue(self):
        with self._lock:
            if self.head is None:
                return None
            data = self.head.data
            self.head = self.head.next
            if self.head is None:
                self.tail = None
            self._size -= 1
            return data

    def is_empty(self):
        with self._lock:
            return self._size == 0
    
    def get_all(self):
        with self._lock:
            items = []
            current = self.head
            while current:
                items.append(current.data)
                current = current.next
            return items
    
    def clear(self):
        with self._lock:
            self.head = None
            self.tail = None
            self._size = 0

# ==============================================================================
# LO4: FIREWALL MANAGER
# ==============================================================================

class FirewallManager:
    PROTECTED_IPS = ['127.0.0.1', 'localhost', '0.0.0.0', '255.255.255.255']
    
    def __init__(self):
        self.blocked_ips = set()
        self.iptables_available = self._check_iptables()
    
    def _check_iptables(self):
        try:
            result = subprocess.run(['which', 'iptables'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def block_ip(self, ip_address):
        if not self.iptables_available:
            return False, "iptables not installed"
        
        if ip_address in self.PROTECTED_IPS:
            return False, f"Cannot block protected IP ({ip_address})"
        
        if ip_address in self.blocked_ips:
            return False, "IP already blocked"
        
        if not self._is_valid_ip(ip_address):
            return False, "Invalid IP format"
        
        try:
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.blocked_ips.add(ip_address)
            return True, f"🛡️ BLOCKED: {ip_address}"
        except subprocess.CalledProcessError as e:
            return False, f"iptables error (need root)"
        except Exception as e:
            return False, str(e)
    
    def unblock_ip(self, ip_address):
        if not self.iptables_available:
            return False, "iptables not available"
        
        if ip_address not in self.blocked_ips:
            return False, "IP not blocked"
        
        try:
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.blocked_ips.remove(ip_address)
            return True, f"✅ UNBLOCKED: {ip_address}"
        except Exception as e:
            return False, str(e)
    
    def get_blocked_list(self):
        return list(self.blocked_ips)
    
    def is_blocked(self, ip_address):
        return ip_address in self.blocked_ips
    
    def _is_valid_ip(self, ip):
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False

# ==============================================================================
# LO2 & LO4: NIDS CORE LOGIC - MORE ALERTS
# ==============================================================================

class NIDS:
    def __init__(self, iface=None):
        self.iface = iface
        self.packet_queue = CustomQueue()       
        self.alert_queue = CustomQueue()        
        self.results = DiscoveryStorage()       
        self.stop_event = threading.Event()
        self.is_running = False

        self.packet_counts = defaultdict(lambda: collections.deque())
        self.syn_scan_tracking = defaultdict(lambda: collections.deque())
        
        # Alert cooldown settings
        self.alert_cooldown = defaultdict(float)
        self.COOLDOWN_SECONDS = 0.5
        self.alert_stats = defaultdict(int)
        
        self.firewall = FirewallManager()
        self.detected_attackers = set()
        self.selected_attack_ip = None
        self.selected_block_ip = None

    def enqueue_packet(self, pkt):
        if scapy.IP in pkt:
            data = {
                'src': pkt[scapy.IP].src,
                'dst': pkt[scapy.IP].dst,
                'time': time.time(),
            }
            if scapy.TCP in pkt:
                tcp = pkt[scapy.TCP]
                data['sport'] = tcp.sport
                data['dport'] = tcp.dport
                data['flags'] = str(tcp.flags)
            self.packet_queue.enqueue(data)

    def sniffer_thread(self):
        try:
            scapy.sniff(
                iface=self.iface,
                prn=self.enqueue_packet,
                store=False, 
                stop_filter=lambda x: self.stop_event.is_set()
            )
        except Exception as e:
            self.alert_queue.enqueue(f"CRITICAL: Sniffer Error - {str(e)}")

    def analyzer_thread(self):
        while not self.stop_event.is_set():
            pkt = self.packet_queue.dequeue()
            if pkt:
                self.process_packet(pkt)
            else:
                time.sleep(0.01)

    def process_packet(self, pkt):
        src = pkt['src']
        now = pkt['time']

        # Skip if IP is blocked
        if self.firewall.is_blocked(src):
            return

        # RULE 1: DoS / Flood Detection (>100 pps)
        self.packet_counts[src].append(now)
        cutoff = now - 1.0
        while self.packet_counts[src] and self.packet_counts[src][0] < cutoff:
            self.packet_counts[src].popleft()

        if len(self.packet_counts[src]) > 100:
            alert = f"🚨 DoS/Flood from {src} ({len(self.packet_counts[src])} pps)"
            self.detected_attackers.add(src)
            self._trigger_alert(alert, src, "DOS")

        # RULE 2: SYN Port Scan Detection
        if 'flags' in pkt and 'S' in pkt['flags']:
            dport = pkt.get('dport', 0)
            self.syn_scan_tracking[src].append((now, dport))
            scan_cutoff = now - 5.0
            while self.syn_scan_tracking[src] and self.syn_scan_tracking[src][0][0] < scan_cutoff:
                self.syn_scan_tracking[src].popleft()

            unique_ports = len({entry[1] for entry in self.syn_scan_tracking[src]})
            if unique_ports > 30:
                alert = f"🔍 Port Scan from {src} ({unique_ports} ports)"
                self.detected_attackers.add(src)
                self._trigger_alert(alert, src, "SCAN")

    def _trigger_alert(self, message, src_ip, alert_type):
        now = time.time()
        cooldown_key = f"{src_ip}:{alert_type}"
        
        if now - self.alert_cooldown[cooldown_key] < self.COOLDOWN_SECONDS:
            self.alert_stats[cooldown_key] += 1
            return
        
        suppressed = self.alert_stats[cooldown_key]
        if suppressed > 0:
            message = f"{message} [+{suppressed} alerts]"
            self.alert_stats[cooldown_key] = 0
        
        self.alert_cooldown[cooldown_key] = now
        self.alert_queue.enqueue(message)
        self.results.insert(message)
        print(f"\n[!!!] {message}")

    def block_ip(self, ip_address):
        success, message = self.firewall.block_ip(ip_address)
        if success:
            alert = f"🛡️ BLOCKED: {ip_address}"
            self.alert_queue.enqueue(alert)
            self.results.insert(alert)
            if self.selected_attack_ip == ip_address:
                self.selected_attack_ip = None
            if ip_address in self.packet_counts:
                self.packet_counts[ip_address].clear()
            if ip_address in self.syn_scan_tracking:
                self.syn_scan_tracking[ip_address].clear()
        return success, message
    
    def unblock_ip(self, ip_address):
        success, message = self.firewall.unblock_ip(ip_address)
        if success:
            alert = f"✅ UNBLOCKED: {ip_address} - Alerts RESUMED"
            self.alert_queue.enqueue(alert)
            self.results.insert(alert)
            for key in list(self.alert_cooldown.keys()):
                if ip_address in key:
                    del self.alert_cooldown[key]
        return success, message
    
    def set_attack_ip(self, ip_address):
        self.selected_attack_ip = ip_address
    
    def set_block_ip(self, ip_address):
        self.selected_block_ip = ip_address
    
    def get_attack_ip(self):
        return self.selected_attack_ip
    
    def get_block_ip(self):
        return self.selected_block_ip
    
    def get_attackers(self):
        return list(self.detected_attackers)
    
    def get_blocked_ips(self):
        return self.firewall.get_blocked_list()

    def start(self):
        if not self.iface:
            return False
        self.is_running = True
        self.stop_event.clear()
        self.t1 = threading.Thread(target=self.sniffer_thread, daemon=True)
        self.t2 = threading.Thread(target=self.analyzer_thread, daemon=True)
        self.t1.start()
        self.t2.start()
        return True

    def stop(self):
        self.stop_event.set()
        self.is_running = False
        time.sleep(0.5)

    def get_alerts(self):
        alerts = []
        while not self.alert_queue.is_empty():
            alerts.append(self.alert_queue.dequeue())
        return alerts
    
    def get_stats(self):
        return dict(self.alert_stats)
    
    def clear_logs(self):
        self.results.clear()
        self.alert_queue.clear()
        self.alert_stats.clear()
        self.alert_cooldown.clear()
        self.packet_counts.clear()
        self.syn_scan_tracking.clear()
        self.detected_attackers.clear()

# ==============================================================================
# LOGIN SYSTEM
# ==============================================================================

class LoginSystem(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Nexus Login Portal")
        self.geometry("950x650")
        self.minsize(900, 600)
        self.configure(fg_color=Colors.BG_DARK)

        # Create user file if it doesn't exist
        if not os.path.exists(USER_FILE):
            with open(USER_FILE, "w") as f:
                pass  # Create empty file

        # Main Container
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color=Colors.BG_CARD)
        self.main_frame.pack(pady=40, padx=40, fill="both", expand=True)

        self.show_login_screen()

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # ================= UI SCREENS =================

    def show_login_screen(self):
        self.clear_frame()

        # Title
        ctk.CTkLabel(
            self.main_frame, 
            text="Welcome to Nexus", 
            font=("Roboto", 24, "bold"), 
            text_color=Colors.PRIMARY
        ).pack(pady=(30, 20))

        # Username entry
        self.username_entry = ctk.CTkEntry(
            self.main_frame, 
            width=250, 
            placeholder_text="Username", 
            fg_color=Colors.BG_FRAME
        )
        self.username_entry.pack(pady=10)
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())

        # Password entry
        self.password_entry = ctk.CTkEntry(
            self.main_frame, 
            width=250, 
            placeholder_text="Password", 
            show="*", 
            fg_color=Colors.BG_FRAME
        )
        self.password_entry.pack(pady=10)
        self.password_entry.bind('<Return>', lambda e: self.handle_login())

        # Login button
        ctk.CTkButton(
            self.main_frame, 
            text="Login", 
            width=250, 
            command=self.handle_login, 
            fg_color=Colors.PRIMARY
        ).pack(pady=(20, 10))
        
        # Create account button
        ctk.CTkButton(
            self.main_frame, 
            text="Create Account", 
            fg_color="transparent", 
            border_width=1, 
            width=250, 
            command=self.show_register_screen,
            border_color=Colors.BORDER
        ).pack(pady=10)

    def show_register_screen(self):
        self.clear_frame()

        # Title
        ctk.CTkLabel(
            self.main_frame, 
            text="Join Nexus", 
            font=("Roboto", 24, "bold"), 
            text_color=Colors.PRIMARY
        ).pack(pady=(30, 20))

        # Username entry
        self.reg_user = ctk.CTkEntry(
            self.main_frame, 
            width=250, 
            placeholder_text="Choose Username", 
            fg_color=Colors.BG_FRAME
        )
        self.reg_user.pack(pady=10)
        self.reg_user.bind('<Return>', lambda e: self.reg_pass.focus())

        # Password entry
        self.reg_pass = ctk.CTkEntry(
            self.main_frame, 
            width=250, 
            placeholder_text="Choose Password", 
            show="*", 
            fg_color=Colors.BG_FRAME
        )
        self.reg_pass.pack(pady=10)
        self.reg_pass.bind('<Return>', lambda e: self.handle_register())

        # Register button
        ctk.CTkButton(
            self.main_frame, 
            text="Register", 
            width=250, 
            command=self.handle_register, 
            fg_color=Colors.SUCCESS
        ).pack(pady=(20, 10))
        
        # Back button
        ctk.CTkButton(
            self.main_frame, 
            text="Back to Login", 
            fg_color="transparent", 
            command=self.show_login_screen, 
            border_width=1, 
            border_color=Colors.BORDER
        ).pack()

    # ================= LOGIC =================

    def handle_register(self):
        u = self.reg_user.get().strip()
        p = self.reg_pass.get().strip()
        
        if not u or not p:
            messagebox.showwarning("Input Error", "Please fill in all fields")
            return

        # Check if user already exists
        if os.path.exists(USER_FILE):
            with open(USER_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and line.split(",")[0] == u:
                        messagebox.showerror("Error", "Username already exists!")
                        return

        # Save user
        with open(USER_FILE, "a") as f:
            f.write(f"{u},{p}\n")
        
        messagebox.showinfo("Success", "Account created successfully!")
        self.show_login_screen()

    def handle_login(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()

        if not u or not p:
            messagebox.showwarning("Input Error", "Please fill in all fields")
            return

        if not os.path.exists(USER_FILE) or os.path.getsize(USER_FILE) == 0:
            messagebox.showerror("Error", "No users found. Please register first.")
            return

        # Check credentials
        with open(USER_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) >= 2:
                    user, password = parts[0], parts[1]
                    if u == user and p == password:
                        messagebox.showinfo("Success", f"Welcome, {u}!")
                        # Open NIDPS and close login
                        self.open_nidps(u)
                        return
        
        messagebox.showerror("Failed", "Invalid username or password")

    def open_nidps(self, username):
        """Open NIDPS and close login window"""
        self.destroy()  # Close login window
        app = NIDSApp(username)
        app.mainloop()

# ==============================================================================
# LO5: GRAPHICAL USER INTERFACE (Modified to include logout)
# ==============================================================================

class NIDSApp(ctk.CTk):
    def __init__(self, username):
        super().__init__()

        self.username = username
        self.title(f"🛡️ NIDPS - Network Intrusion Detection System (Logged in as: {username})")
        self.geometry("950x650")
        self.minsize(900, 600)
        self.configure(fg_color=Colors.BG_DARK)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        self.nids = None
        self.update_job = None
        self.alert_count = 0

        self._create_header()
        self._create_controls()
        self._create_stats()
        self._create_actions()
        self._create_log()
        self._create_footer()

    def _create_header(self):
        header = ctk.CTkFrame(self, fg_color=Colors.BG_FRAME, height=50)
        header.grid(row=0, column=0, sticky="ew")
        
        ctk.CTkLabel(
            header, 
            text="🛡️ NIDPS", 
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=Colors.PRIMARY
        ).pack(side="left", padx=20, pady=15)
        
        ctk.CTkLabel(
            header, 
            text="Network Intrusion Detection & Prevention System", 
            font=ctk.CTkFont(size=10),
            text_color=Colors.TEXT_DIM
        ).pack(side="left", padx=10, pady=18)
        
        # User info
        ctk.CTkLabel(
            header,
            text=f"👤 {self.username}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=Colors.SUCCESS
        ).pack(side="right", padx=10, pady=18)
        
        self.status_label = ctk.CTkLabel(
            header, 
            text="● Idle", 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=Colors.TEXT_DIM
        )
        self.status_label.pack(side="right", padx=10, pady=18)

    def _create_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=Colors.BG_CARD, corner_radius=8)
        ctrl.grid(row=1, column=0, padx=15, pady=10, sticky="ew")
        
        ctk.CTkLabel(
            ctrl, 
            text="Network Interface:", 
            font=ctk.CTkFont(weight="bold", size=12),
            text_color=Colors.TEXT_MAIN
        ).pack(side="left", padx=15, pady=12)
        
        self.interface_combo = ctk.CTkComboBox(
            ctrl, 
            values=self.get_interfaces(), 
            width=180,
            fg_color=Colors.BG_FRAME,
            border_color=Colors.BORDER,
            button_color=Colors.PRIMARY
        )
        self.interface_combo.pack(side="left", padx=10, pady=12)
        self.interface_combo.set("Select Interface")
        
        self.start_btn = ctk.CTkButton(
            ctrl, 
            text="▶ START", 
            command=self.start_monitoring, 
            fg_color=Colors.SUCCESS,
            hover_color="#2ea043",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=100,
            height=32
        )
        self.start_btn.pack(side="right", padx=8, pady=12)
        
        self.stop_btn = ctk.CTkButton(
            ctrl, 
            text="⏹ STOP", 
            command=self.stop_monitoring, 
            fg_color=Colors.DANGER,
            hover_color="#da3633",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=80,
            height=32,
            state="disabled"
        )
        self.stop_btn.pack(side="right", padx=8, pady=12)

    def _create_stats(self):
        stats = ctk.CTkFrame(self, fg_color=Colors.BG_CARD, corner_radius=8)
        stats.grid(row=2, column=0, padx=15, pady=8, sticky="ew")
        stats.grid_columnconfigure((0,1,2,3), weight=1)
        
        self.alert_count_label = ctk.CTkLabel(
            stats, 
            text="📊 Alerts: 0", 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.PRIMARY
        )
        self.alert_count_label.grid(row=0, column=0, padx=15, pady=10)
        
        self.suppressed_label = ctk.CTkLabel(
            stats, 
            text="🔇 Suppressed: 0", 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.WARNING
        )
        self.suppressed_label.grid(row=0, column=1, padx=15, pady=10)
        
        self.blocked_count_label = ctk.CTkLabel(
            stats, 
            text="🚫 Blocked: 0", 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.DANGER
        )
        self.blocked_count_label.grid(row=0, column=2, padx=15, pady=10)
        
        self.attackers_label = ctk.CTkLabel(
            stats, 
            text="⚠️ Attackers: 0", 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.PURPLE
        )
        self.attackers_label.grid(row=0, column=3, padx=15, pady=10)

    def _create_actions(self):
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=3, column=0, padx=15, pady=8, sticky="ew")
        actions.grid_columnconfigure((0,1), weight=1)
        
        # BLOCK Panel
        block = ctk.CTkFrame(
            actions, 
            fg_color="#2d1414", 
            corner_radius=8, 
            border_width=2, 
            border_color=Colors.DANGER
        )
        block.grid(row=0, column=0, padx=8, sticky="ew")
        
        ctk.CTkLabel(
            block, 
            text="🛑 BLOCK", 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.DANGER
        ).grid(row=0, column=0, columnspan=2, padx=12, pady=8)
        
        self.attacker_combo = ctk.CTkComboBox(
            block, 
            values=["No attackers"],
            command=self.on_attack_ip_select,
            width=160,
            fg_color=Colors.BG_FRAME,
            border_color=Colors.BORDER,
            button_color=Colors.DANGER,
            state="readonly"
        )
        self.attacker_combo.grid(row=1, column=0, columnspan=2, padx=12, pady=4, sticky="ew")
        self.attacker_combo.set("No attackers")
        
        self.attack_selected_label = ctk.CTkLabel(
            block, 
            text="Selected: None", 
            text_color=Colors.WARNING,
            font=ctk.CTkFont(size=10, weight="bold")
        )
        self.attack_selected_label.grid(row=2, column=0, columnspan=2, padx=12, pady=3, sticky="w")
        
        self.block_btn = ctk.CTkButton(
            block, 
            text="🛡️ BLOCK IP", 
            command=self.block_selected_ip, 
            fg_color=Colors.DANGER,
            hover_color="#da3633",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=30,
            state="disabled"
        )
        self.block_btn.grid(row=3, column=0, columnspan=2, padx=12, pady=8, sticky="ew")
        
        # UNBLOCK Panel
        unblock = ctk.CTkFrame(
            actions, 
            fg_color="#142d14", 
            corner_radius=8, 
            border_width=2, 
            border_color=Colors.SUCCESS
        )
        unblock.grid(row=0, column=1, padx=8, sticky="ew")
        
        ctk.CTkLabel(
            unblock, 
            text="✅ UNBLOCK", 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.SUCCESS
        ).grid(row=0, column=0, columnspan=2, padx=12, pady=8)
        
        self.blocked_combo = ctk.CTkComboBox(
            unblock, 
            values=["No blocked IPs"],
            command=self.on_block_ip_select,
            width=160,
            fg_color=Colors.BG_FRAME,
            border_color=Colors.BORDER,
            button_color=Colors.SUCCESS,
            state="readonly"
        )
        self.blocked_combo.grid(row=1, column=0, columnspan=2, padx=12, pady=4, sticky="ew")
        self.blocked_combo.set("No blocked IPs")
        
        self.block_selected_label = ctk.CTkLabel(
            unblock, 
            text="Selected: None", 
            text_color=Colors.WARNING,
            font=ctk.CTkFont(size=10, weight="bold")
        )
        self.block_selected_label.grid(row=2, column=0, columnspan=2, padx=12, pady=3, sticky="w")
        
        self.unblock_btn = ctk.CTkButton(
            unblock, 
            text="✅ UNBLOCK IP", 
            command=self.unblock_selected_ip, 
            fg_color=Colors.SUCCESS,
            hover_color="#2ea043",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=30,
            state="disabled"
        )
        self.unblock_btn.grid(row=3, column=0, columnspan=2, padx=12, pady=8, sticky="ew")

    def _create_log(self):
        log = ctk.CTkFrame(self, fg_color=Colors.BG_CARD, corner_radius=8)
        log.grid(row=4, column=0, padx=15, pady=8, sticky="nsew")
        
        log_header = ctk.CTkFrame(log, fg_color="transparent")
        log_header.pack(fill="x", padx=12, pady=6)
        
        ctk.CTkLabel(
            log_header, 
            text="📋 Live Alert Log", 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Colors.PRIMARY
        ).pack(side="left")
        
        ctk.CTkButton(
            log_header, 
            text="Clear", 
            command=self.clear_logs, 
            fg_color=Colors.BG_FRAME,
            hover_color=Colors.BORDER,
            text_color=Colors.TEXT_MAIN,
            font=ctk.CTkFont(size=10),
            width=60,
            height=24
        ).pack(side="right")
        
        self.log_textbox = ctk.CTkTextbox(
            log, 
            state="disabled",
            fg_color=Colors.BG_FRAME,
            border_color=Colors.BORDER,
            border_width=1,
            corner_radius=6,
            font=ctk.CTkFont(family="Courier", size=9)
        )
        self.log_textbox.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _create_footer(self):
        """Create footer with logout button"""
        footer = ctk.CTkFrame(self, fg_color=Colors.BG_FRAME, height=40)
        footer.grid(row=5, column=0, sticky="ew", padx=15, pady=(0, 10))
        
        ctk.CTkButton(
            footer,
            text="🚪 Logout",
            command=self.logout,
            fg_color=Colors.WARNING,
            hover_color="#b87c1a",
            font=ctk.CTkFont(size=11, weight="bold"),
            width=80,
            height=28
        ).pack(side="right", padx=15, pady=6)

    def get_interfaces(self):
        try:
            return scapy.get_if_list()
        except:
            return ["Error"]

    def start_monitoring(self):
        iface = self.interface_combo.get()
        if iface == "Select Interface" or "Error" in iface:
            self.status_label.configure(text="● Error - Select Interface", text_color=Colors.DANGER)
            return

        self.nids = NIDS(iface=iface)
        if self.nids.start():
            self.start_btn.configure(state="disabled", fg_color=Colors.TEXT_MUTED)
            self.stop_btn.configure(state="normal")
            self.status_label.configure(text="● Monitoring", text_color=Colors.SUCCESS)
            self.log_to_ui(f"[✓] Started on {iface}\n")
            
            if not self.nids.firewall.iptables_available:
                self.log_to_ui("[⚠] iptables not found\n")
            
            self.alert_count = 0
            self.schedule_ui_update()
        else:
            self.status_label.configure(text="● Failed", text_color=Colors.DANGER)

    def stop_monitoring(self):
        if self.nids:
            self.nids.stop()
            self.start_btn.configure(state="normal", fg_color=Colors.SUCCESS)
            self.stop_btn.configure(state="disabled")
            self.status_label.configure(text="● Stopped", text_color=Colors.WARNING)
            self.log_to_ui("[✓] Stopped\n")
            if self.update_job:
                self.after_cancel(self.update_job)

    def schedule_ui_update(self):
        if self.nids and self.nids.is_running:
            alerts = self.nids.get_alerts()
            for alert in alerts:
                self.log_to_ui(f"[ALERT] {alert}\n")
                self.alert_count += 1
            
            self.update_attacker_list()
            self.update_blocked_list()
            self.update_stats()
            self.check_buttons()
            
            self.update_job = self.after(100, self.schedule_ui_update)

    def update_attacker_list(self):
        if self.nids:
            attackers = self.nids.get_attackers()
            blocked = self.nids.get_blocked_ips()
            available = [ip for ip in attackers if ip not in blocked]
            
            current = self.attacker_combo.get()
            if available:
                self.attacker_combo.configure(values=available)
                if current == "No attackers":
                    self.attacker_combo.set(available[0])
                    self.on_attack_ip_select(available[0])
            else:
                self.attacker_combo.configure(values=["No attackers"])
                self.attacker_combo.set("No attackers")
                self.on_attack_ip_select("No attackers")
            
            self.attackers_label.configure(text=f"⚠️ Attackers: {len(attackers)}")

    def update_blocked_list(self):
        if self.nids:
            blocked = self.nids.get_blocked_ips()
            
            current = self.blocked_combo.get()
            if blocked:
                self.blocked_combo.configure(values=blocked)
                if current == "No blocked IPs":
                    self.blocked_combo.set(blocked[0])
                    self.on_block_ip_select(blocked[0])
            else:
                self.blocked_combo.configure(values=["No blocked IPs"])
                self.blocked_combo.set("No blocked IPs")
                self.on_block_ip_select("No blocked IPs")
            
            self.blocked_count_label.configure(text=f"🚫 Blocked: {len(blocked)}")

    def update_stats(self):
        self.alert_count_label.configure(text=f"📊 Alerts: {self.alert_count}")
        if self.nids:
            stats = self.nids.get_stats()
            total_suppressed = sum(stats.values())
            self.suppressed_label.configure(text=f"🔇 Suppressed: {total_suppressed}")

    def check_buttons(self):
        if self.nids:
            attack_ip = self.nids.get_attack_ip()
            blocked = self.nids.get_blocked_ips()
            
            if attack_ip and attack_ip not in blocked:
                self.block_btn.configure(state="normal", fg_color=Colors.DANGER)
                self.attack_selected_label.configure(text=f"Selected: {attack_ip}")
            else:
                self.block_btn.configure(state="disabled", fg_color=Colors.BG_FRAME)
                if not attack_ip:
                    self.attack_selected_label.configure(text="Selected: None")
            
            block_ip = self.nids.get_block_ip()
            
            if block_ip and block_ip in blocked:
                self.unblock_btn.configure(state="normal", fg_color=Colors.SUCCESS)
                self.block_selected_label.configure(text=f"Selected: {block_ip}")
            else:
                self.unblock_btn.configure(state="disabled", fg_color=Colors.BG_FRAME)
                if not block_ip:
                    self.block_selected_label.configure(text="Selected: None")

    def on_attack_ip_select(self, value):
        if self.nids and value and value != "No attackers":
            self.nids.set_attack_ip(value)
            self.check_buttons()

    def on_block_ip_select(self, value):
        if self.nids and value and value != "No blocked IPs":
            self.nids.set_block_ip(value)
            self.check_buttons()

    def block_selected_ip(self):
        if self.nids:
            ip = self.nids.get_attack_ip()
            if ip:
                success, msg = self.nids.block_ip(ip)
                self.log_to_ui(f"[ACTION] {msg}\n")
                self.nids.set_attack_ip(None)
                self.check_buttons()
                self.update_blocked_list()
                self.update_attacker_list()

    def unblock_selected_ip(self):
        if self.nids:
            ip = self.nids.get_block_ip()
            if ip:
                success, msg = self.nids.unblock_ip(ip)
                self.log_to_ui(f"[ACTION] {msg}\n")
                self.nids.set_block_ip(None)
                self.check_buttons()
                self.update_blocked_list()
                self.update_attacker_list()

    def clear_logs(self):
        if self.nids:
            self.nids.clear_logs()
            self.log_textbox.configure(state="normal")
            self.log_textbox.delete("1.0", "end")
            self.log_textbox.insert("1.0", "[SYSTEM] Logs cleared\n")
            self.log_textbox.configure(state="disabled")
            self.alert_count = 0
            self.update_stats()
            self.update_attacker_list()
            self.update_blocked_list()

    def log_to_ui(self, message):
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", message)
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def logout(self):
        """Logout and return to login screen"""
        if self.nids and self.nids.is_running:
            self.nids.stop()
        self.destroy()
        login = LoginSystem()
        login.mainloop()

    def on_close(self):
        """Handle window close event"""
        if self.nids and self.nids.is_running:
            self.nids.stop()
        self.destroy()

# ==============================================================================
# MAIN
# ==============================================================================

def main():
    print("\n" + "="*60)
    print("🛡️ Nexus - Network Intrusion Detection & Prevention System")
    print("="*60)
    print("⚠️  MUST RUN AS ROOT: sudo -E python3 app.py")
    print("="*60 + "\n")
    
    # Start with login screen
    app = LoginSystem()
    app.protocol("WM_DELETE_WINDOW", app.destroy)
    app.mainloop()

if __name__ == "__main__":
    main()


 



