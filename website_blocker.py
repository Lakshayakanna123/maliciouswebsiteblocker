import tkinter as tk
import os
import webbrowser
import platform
import requests
import threading
import time
from urllib.parse import urlparse
import sqlite3
from datetime import datetime
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import dns.resolver
import dns.exception
import whois

# Load environment variables manually from .env file
def load_dotenv(dotenv_path=".env"):
    if os.path.exists(dotenv_path):
        with open(dotenv_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    val = value.strip()
                    # Strip matching double or single quotes around the value
                    if len(val) >= 2 and ((val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'"))):
                        val = val[1:-1]
                    os.environ[key.strip()] = val

# Run load_dotenv
load_dotenv()

# Domain extraction helper
def extract_domain(url):
    if not url.startswith(("http://", "https://")):
        url_with_scheme = "http://" + url
    else:
        url_with_scheme = url
    try:
        parsed = urlparse(url_with_scheme)
        domain = parsed.netloc
        if ":" in domain:
            domain = domain.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return url

class SecurityDatabase:
    def __init__(self, db_path="security_stats.db"):
        self.db_path = db_path
        self.init_db()
        self.sync_blocked_domains()
        
    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    url TEXT,
                    status TEXT,
                    score INTEGER
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS block_history (
                    domain TEXT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass
            
    def sync_blocked_domains(self):
        system_name = platform.system()
        if system_name == "Windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        elif system_name in ("Linux", "Darwin"):
            hosts_path = "/etc/hosts"
        else:
            return
            
        if not os.path.exists(hosts_path):
            return
            
        try:
            blocked_domains = set()
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == "127.0.0.1":
                            domain = parts[1]
                            if domain.startswith("www."):
                                domain = domain[4:]
                            blocked_domains.add(domain)
                            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM block_history")
            for domain in blocked_domains:
                cursor.execute("INSERT OR REPLACE INTO block_history (domain) VALUES (?)", (domain,))
            conn.commit()
            conn.close()
        except Exception:
            pass
            
    def log_scan(self, url, status, score):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history (url, status, score) VALUES (?, ?, ?)",
                (url, status, score)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
            
    def log_block(self, domain):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO block_history (domain) VALUES (?)",
                (domain,)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
            
    def log_unblock(self, domain):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM block_history WHERE domain = ?",
                (domain,)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
            
    def get_statistics(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            total_scans = cursor.fetchone()[0]
            
            # Total blocked
            cursor.execute("SELECT COUNT(*) FROM block_history")
            total_blocked = cursor.fetchone()[0]
            
            # Total malicious detections
            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'Malicious'")
            total_malicious = cursor.fetchone()[0]
            
            # Today's scans
            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE date(timestamp, 'localtime') = date('now', 'localtime')")
            todays_scans = cursor.fetchone()[0]
            
            # Last scan timestamp
            cursor.execute("SELECT datetime(max(timestamp), 'localtime') FROM scan_history")
            last_scan_raw = cursor.fetchone()[0]
            if last_scan_raw:
                try:
                    dt = datetime.strptime(last_scan_raw, "%Y-%m-%d %H:%M:%S")
                    last_scan = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    last_scan = last_scan_raw
            else:
                last_scan = "N/A"
                
            # Pie chart counts
            cursor.execute("SELECT status, COUNT(*) FROM scan_history GROUP BY status")
            counts = {'Safe': 0, 'Malicious': 0, 'Unknown': 0}
            for status, count in cursor.fetchall():
                if status in counts:
                    counts[status] = count
                    
            conn.close()
            return {
                'total_scans': total_scans,
                'total_blocked': total_blocked,
                'total_malicious': total_malicious,
                'todays_scans': todays_scans,
                'last_scan': last_scan,
                'pie_counts': counts
            }
        except Exception:
            return {
                'total_scans': 0,
                'total_blocked': 0,
                'total_malicious': 0,
                'todays_scans': 0,
                'last_scan': "N/A",
                'pie_counts': {'Safe': 0, 'Malicious': 0, 'Unknown': 0}
            }

class SecurityCommandCenterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WebsiteTotal Command Center")
        
        # Configure deep background
        self.root.configure(bg="#08090f")
        
        # Start in standard windowed mode centered on screen
        self.is_fullscreen = False
        width = 1400
        height = 900
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.bind("<Escape>", self.toggle_fullscreen_event)
        
        # Get settings from env or defaults
        env_key = os.getenv("VT_API_KEY")
        if not env_key or env_key.strip() == "" or env_key == "YOUR_VIRUSTOTAL_API_KEY":
            self.api_key = "b08753e41ef61863bd3a2e667cc093b41ca12b36232be34dfa352a39a9fec55"
        else:
            self.api_key = env_key
        self.password = os.getenv("APP_PASSWORD", "admin")
        
        # Threat scanner states: "idle", "scanning", "safe", "malicious"
        self.scan_state = "idle"
        self.spinner_angle = 0
        self.pulse_grow = True
        self.pulse_radius = 40
        
        # Risk score visualization states
        self.current_risk_score = 0
        self._anim_task = None
        
        # Initialize SQLite database stats tracker
        self.db = SecurityDatabase()
        
        # WHOIS intelligence lookup cache
        self.whois_cache = {}
        
        self.setup_ui()
        self.refresh_dashboard_stats()
        self.start_dashboard_background_loop()
        
    def setup_ui(self):
        # Grid weight configuration for responsiveness
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=0) # Header
        self.root.rowconfigure(1, weight=1) # Main Area
        self.root.rowconfigure(2, weight=0) # Footer
        
        # ----------------------------------------------------
        # 1. HEADER PANEL
        # ----------------------------------------------------
        header = tk.Frame(self.root, bg="#08090f")
        header.grid(row=0, column=0, sticky="ew", padx=40, pady=(30, 15))
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)
        
        title_frame = tk.Frame(header, bg="#08090f")
        title_frame.grid(row=0, column=0, sticky="w")
        
        title = tk.Label(
            title_frame, 
            text="🛡️ WEBSITETOTAL COMMAND CENTER", 
            font=("Segoe UI", 20, "bold"), 
            bg="#08090f", 
            fg="#00f0ff"
        )
        title.pack(anchor="w")
        
        subtitle = tk.Label(
            title_frame, 
            text="Active Hosts Integrity Protection & Real-time Threat Intelligence Database Check", 
            font=("Segoe UI", 10), 
            bg="#08090f", 
            fg="#6b7280"
        )
        subtitle.pack(anchor="w", pady=(4, 0))
        
        # Window settings control frame (custom fullscreen/exit buttons removed as per user request)
        control_frame = tk.Frame(header, bg="#08090f")
        control_frame.grid(row=0, column=1, sticky="e")
        self.fs_btn = None
        
        # ----------------------------------------------------
        # 2. MAIN DASHBOARD GRID
        # ----------------------------------------------------
        dashboard = tk.Frame(self.root, bg="#08090f")
        dashboard.grid(row=1, column=0, sticky="nsew", padx=40, pady=10)
        dashboard.columnconfigure(0, weight=1) # Left panel weight
        dashboard.columnconfigure(1, weight=1) # Middle panel weight (right_card)
        dashboard.columnconfigure(2, weight=1) # Right panel weight (stats_card)
        dashboard.rowconfigure(0, weight=1)
        
        # --- LEFT PANEL: MITIGATION CONTROL BOARD ---
        left_card = tk.Frame(dashboard, bg="#121625", bd=0, highlightthickness=1, highlightbackground="#263050")
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)
        left_card.columnconfigure(0, weight=1)
        
        left_title = tk.Label(
            left_card, 
            text="OPERATIONS AND THREAT MITIGATION", 
            font=("Segoe UI", 13, "bold"), 
            bg="#121625", 
            fg="#00f0ff", 
            anchor="w"
        )
        left_title.pack(fill="x", padx=30, pady=(30, 20))
        
        # Target Scan URL Input
        scan_grp = tk.Frame(left_card, bg="#121625")
        scan_grp.pack(fill="x", padx=30, pady=12)
        tk.Label(scan_grp, text="TARGET SCAN RESOURCE (URL OR HOSTNAME)", font=("Segoe UI", 9, "bold"), bg="#121625", fg="#9ca3af").pack(anchor="w")
        self.url_entry = tk.Entry(
            scan_grp, 
            font=("Segoe UI", 11), 
            bg="#0a0b10", 
            fg="#ffffff", 
            insertbackground="#00f0ff", 
            bd=0, 
            highlightthickness=1, 
            highlightbackground="#263050", 
            highlightcolor="#00f0ff"
        )
        self.url_entry.pack(fill="x", pady=(6, 0), ipady=8)
        self.url_entry.insert(0, "http://")
        
        # Domain Blocker Input
        block_grp = tk.Frame(left_card, bg="#121625")
        block_grp.pack(fill="x", padx=30, pady=12)
        tk.Label(block_grp, text="WEBSITE DOMAIN TO MITIGATE (BLOCK / UNBLOCK)", font=("Segoe UI", 9, "bold"), bg="#121625", fg="#9ca3af").pack(anchor="w")
        self.website_entry = tk.Entry(
            block_grp, 
            font=("Segoe UI", 11), 
            bg="#0a0b10", 
            fg="#ffffff", 
            insertbackground="#00f0ff", 
            bd=0, 
            highlightthickness=1, 
            highlightbackground="#263050", 
            highlightcolor="#00f0ff"
        )
        self.website_entry.pack(fill="x", pady=(6, 0), ipady=8)
        
        # Security Password Input
        pass_grp = tk.Frame(left_card, bg="#121625")
        pass_grp.pack(fill="x", padx=30, pady=12)
        tk.Label(pass_grp, text="ADMIN SECURITY ACCESS PASSWORD", font=("Segoe UI", 9, "bold"), bg="#121625", fg="#9ca3af").pack(anchor="w")
        self.password_entry = tk.Entry(
            pass_grp, 
            font=("Segoe UI", 11), 
            show="*", 
            bg="#0a0b10", 
            fg="#ffffff", 
            insertbackground="#00f0ff", 
            bd=0, 
            highlightthickness=1, 
            highlightbackground="#263050", 
            highlightcolor="#00f0ff"
        )
        self.password_entry.pack(fill="x", pady=(6, 0), ipady=8)
        if self.password == "admin":
            self.password_entry.insert(0, "admin")
            
        # Control Buttons
        btn_grp = tk.Frame(left_card, bg="#121625")
        btn_grp.pack(fill="x", padx=30, pady=(35, 30))
        btn_grp.columnconfigure(0, weight=1)
        btn_grp.columnconfigure(1, weight=1)
        
        # Deploy Scan Button
        self.btn_scan = tk.Button(
            btn_grp, 
            text="🛡️ DEPLOY SECURITY ANALYSIS", 
            font=("Segoe UI", 10, "bold"),
            bg="#00f0ff", 
            fg="#08090f", 
            activebackground="#33f3ff", 
            activeforeground="#08090f",
            bd=0, 
            pady=14, 
            cursor="hand2", 
            command=self.start_scan_thread
        )
        self.btn_scan.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        
        # Mitigate / Block Button
        self.btn_block = tk.Button(
            btn_grp, 
            text="🚫 MITIGATE & BLOCK", 
            font=("Segoe UI", 10, "bold"),
            bg="#ef4444", 
            fg="#ffffff", 
            activebackground="#f87171", 
            activeforeground="#ffffff",
            bd=0, 
            pady=14, 
            cursor="hand2", 
            command=self.block_website
        )
        self.btn_block.grid(row=1, column=0, sticky="ew", padx=(0, 6))
        
        # Restore / Unblock Button
        self.btn_unblock = tk.Button(
            btn_grp, 
            text="🔓 RESTORE ACCESS", 
            font=("Segoe UI", 10, "bold"),
            bg="#2ece7a", 
            fg="#08090f", 
            activebackground="#3ce28c", 
            activeforeground="#08090f",
            bd=0, 
            pady=14, 
            cursor="hand2", 
            command=self.unblock_website
        )
        self.btn_unblock.grid(row=1, column=1, sticky="ew", padx=(6, 0))
        
        # --- RIGHT PANEL: THREAT MONITORING SYSTEM ---
        right_card = tk.Frame(dashboard, bg="#121625", bd=0, highlightthickness=1, highlightbackground="#263050")
        right_card.grid(row=0, column=1, sticky="nsew", padx=(10, 10), pady=0)
        right_card.columnconfigure(0, weight=1)
        right_card.rowconfigure(4, weight=1) # Allow log to take up available height
        
        right_title = tk.Label(
            right_card, 
            text="REAL-TIME THREAT MONITORING", 
            font=("Segoe UI", 13, "bold"), 
            bg="#121625", 
            fg="#00f0ff", 
            anchor="w"
        )
        right_title.grid(row=0, column=0, sticky="ew", padx=30, pady=(30, 10))
        
        # Central Canvas visual feedback indicator
        self.canvas = tk.Canvas(right_card, bg="#121625", highlightthickness=0, width=220, height=240)
        self.canvas.grid(row=1, column=0, pady=(10, 5))
        
        # Pulse/Status label directly inside card layout
        self.status_lbl = tk.Label(
            right_card, 
            text="SECURE RADAR LOADED & STANDBY", 
            font=("Segoe UI", 10, "bold"), 
            bg="#121625", 
            fg="#9ca3af"
        )
        self.status_lbl.grid(row=2, column=0, sticky="ew", pady=(5, 10))
        
        # Scrollable log terminal area
        term_label = tk.Label(
            right_card, 
            text="REAL-TIME SYSTEM AUDIT LOG", 
            font=("Segoe UI", 9, "bold"), 
            bg="#121625", 
            fg="#6b7280", 
            anchor="w"
        )
        term_label.grid(row=3, column=0, sticky="w", padx=30, pady=(15, 2))
        
        term_frame = tk.Frame(right_card, bg="#0a0b10", bd=0, highlightthickness=1, highlightbackground="#263050")
        term_frame.grid(row=4, column=0, sticky="nsew", padx=30, pady=(0, 30))
        term_frame.columnconfigure(0, weight=1)
        term_frame.rowconfigure(0, weight=1)
        
        self.terminal = tk.Text(
            term_frame, 
            bg="#0a0b10", 
            fg="#d1d5db", 
            font=("Consolas", 10), 
            bd=0, 
            wrap="word", 
            state="disabled"
        )
        self.terminal.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        
        scrollbar = tk.Scrollbar(term_frame, orient="vertical", command=self.terminal.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.terminal.config(yscrollcommand=scrollbar.set)
        
        # Color tags configurations for terminal output
        self.terminal.tag_config("info", foreground="#9ca3af")
        self.terminal.tag_config("system", foreground="#00f0ff")
        self.terminal.tag_config("success", foreground="#00ff66")
        self.terminal.tag_config("warning", foreground="#ffaa00")
        self.terminal.tag_config("error", foreground="#ff003c")
        
        # --- RIGHT PANEL: STATISTICS & VISUAL ANALYTICS ---
        stats_card = tk.Frame(dashboard, bg="#121625", bd=0, highlightthickness=1, highlightbackground="#263050")
        stats_card.grid(row=0, column=2, sticky="nsew", padx=(10, 0), pady=0)
        stats_card.columnconfigure(0, weight=1)
        stats_card.rowconfigure(0, weight=0) # Title
        stats_card.rowconfigure(1, weight=0) # Metrics
        stats_card.rowconfigure(2, weight=1) # Chart Plot
        
        stats_title = tk.Label(
            stats_card, 
            text="REAL-TIME TELEMETRY & STATS", 
            font=("Segoe UI", 13, "bold"), 
            bg="#121625", 
            fg="#00f0ff", 
            anchor="w"
        )
        stats_title.grid(row=0, column=0, sticky="ew", padx=30, pady=(30, 15))
        
        metrics_frame = tk.Frame(stats_card, bg="#121625")
        metrics_frame.grid(row=1, column=0, sticky="ew", padx=30, pady=5)
        metrics_frame.columnconfigure(0, weight=1)
        metrics_frame.columnconfigure(1, weight=1)
        
        self.val_total_scans = tk.Label(metrics_frame, text="0", font=("Segoe UI", 10, "bold"), bg="#121625", fg="#00f0ff", anchor="e")
        self.val_total_blocked = tk.Label(metrics_frame, text="0", font=("Segoe UI", 10, "bold"), bg="#121625", fg="#ef4444", anchor="e")
        self.val_total_malicious = tk.Label(metrics_frame, text="0", font=("Segoe UI", 10, "bold"), bg="#121625", fg="#ff3c00", anchor="e")
        self.val_todays_scans = tk.Label(metrics_frame, text="0", font=("Segoe UI", 10, "bold"), bg="#121625", fg="#00ff66", anchor="e")
        self.val_last_scan = tk.Label(metrics_frame, text="N/A", font=("Segoe UI", 9, "bold"), bg="#121625", fg="#9ca3af", anchor="e")
        
        labels_data = [
            ("TOTAL SCAN OPERATIONS", self.val_total_scans),
            ("ACTIVE BLOCK RULES", self.val_total_blocked),
            ("CRITICAL THREAT DETECTED", self.val_total_malicious),
            ("TODAY'S SESSION SCANS", self.val_todays_scans),
            ("LAST DATABASE UPDATE", self.val_last_scan)
        ]
        for idx, (k_text, v_widget) in enumerate(labels_data):
            lbl_key = tk.Label(metrics_frame, text=k_text, font=("Segoe UI", 8, "bold"), bg="#121625", fg="#6b7280", anchor="w")
            lbl_key.grid(row=idx, column=0, sticky="w", pady=4)
            v_widget.grid(row=idx, column=1, sticky="e", pady=4)
            
        # Embedded Matplotlib Donut Chart Frame
        self.chart_frame = tk.Frame(stats_card, bg="#121625")
        self.chart_frame.grid(row=2, column=0, sticky="nsew", padx=30, pady=(15, 30))
        self.chart_frame.columnconfigure(0, weight=1)
        self.chart_frame.rowconfigure(0, weight=1)
        
        # Initialize Matplotlib Figure & Canvas
        self.fig, self.ax = plt.subplots(figsize=(2.8, 2.8), dpi=100)
        self.fig.patch.set_facecolor('#121625')
        self.ax.set_facecolor('#121625')
        
        self.canvas_plot = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas_plot.get_tk_widget().grid(row=0, column=0, sticky="nsew")
        self.canvas_plot.get_tk_widget().configure(bg="#121625")
        
        # ----------------------------------------------------
        # 3. FOOTER
        # ----------------------------------------------------
        footer = tk.Label(
            self.root, 
            text="WEBSITETOTAL THREAT RADAR v2.0 // SYSTEM INTEGRITY SECURED", 
            font=("Consolas", 8), 
            bg="#08090f", 
            fg="#4b5563"
        )
        footer.grid(row=2, column=0, pady=20)
        
        # Setup mouse hover triggers
        self.add_hover_effect(self.btn_scan, "#33f3ff", "#00f0ff", "#08090f", "#08090f")
        self.add_hover_effect(self.btn_block, "#dc2626", "#ef4444", "#ffffff", "#ffffff")
        self.add_hover_effect(self.btn_unblock, "#3ce28c", "#2ece7a", "#08090f", "#08090f")
        
        # Initial status logging
        self.log_terminal("Initializing WebsiteTotal Command Center...", "system")
        self.log_terminal(f"Operating system detected: {platform.system()} ({platform.release()})", "info")
        self.log_terminal("WebsiteTotal scan heuristics engine online.", "system")
        self.log_terminal("Waiting for target input in Control Board.", "info")
        
    def add_hover_effect(self, widget, hover_bg, normal_bg, active_fg, normal_fg):
        widget.bind("<Enter>", lambda e: widget.config(bg=hover_bg, fg=active_fg) if widget["state"] != "disabled" else None)
        widget.bind("<Leave>", lambda e: widget.config(bg=normal_bg, fg=normal_fg) if widget["state"] != "disabled" else None)
        
    def toggle_fullscreen_event(self, event):
        self.toggle_fullscreen()
        
    def toggle_fullscreen(self):
        self.is_fullscreen = not self.is_fullscreen
        self.root.attributes("-fullscreen", self.is_fullscreen)
        if self.is_fullscreen:
            self.fs_btn.config(text="⛶ Windowed")
        else:
            self.fs_btn.config(text="⛶ Fullscreen")
            
    def log_terminal(self, msg, log_type="info"):
        self.terminal.config(state="normal")
        timestamp = time.strftime("[%H:%M:%S] ")
        self.terminal.insert(tk.END, timestamp, "info")
        
        prefix = "[INFO] "
        if log_type == "error":
            prefix = "[ERROR] "
        elif log_type == "success":
            prefix = "[SUCCESS] "
        elif log_type == "warning":
            prefix = "[WARN]  "
        elif log_type == "system":
            prefix = "[SYS]   "
            
        self.terminal.insert(tk.END, prefix, log_type)
        self.terminal.insert(tk.END, msg + "\n", "info" if log_type == "info" else log_type)
        self.terminal.see(tk.END)
        self.terminal.config(state="disabled")

    # ----------------------------------------------------
    # VECTOR GRAPHICS CANVAS DRAWING & RADAR LOOP
    # ----------------------------------------------------
    def draw_status_shield(self):
        self.canvas.delete("all")
        cx, cy = 110, 110
        
        # Outer visual telemetry rings
        self.canvas.create_oval(cx - 95, cy - 95, cx + 95, cy + 95, outline="#1b2135", width=2)
        self.canvas.create_oval(cx - 80, cy - 80, cx + 80, cy + 80, outline="#161b2c", width=1)
        
        if self.scan_state == "idle":
            # Orbiting dial
            self.canvas.create_oval(cx - 65, cy - 65, cx + 65, cy + 65, outline="#263050", width=4)
            # Sweep pointer line
            import math
            rad = math.radians(self.spinner_angle)
            lx = cx + 65 * math.cos(rad)
            ly = cy + 65 * math.sin(rad)
            self.canvas.create_line(cx, cy, lx, ly, fill="#00f0ff", width=2)
            self.canvas.create_arc(cx - 65, cy - 65, cx + 65, cy + 65, start=self.spinner_angle - 45, extent=45, fill="", outline="#00f0ff", width=2)
            
            # Central ready indicator
            self.canvas.create_oval(cx - 32, cy - 32, cx + 32, cy + 32, fill="#121625", outline="#00f0ff", width=2)
            self.canvas.create_text(cx, cy, text="STANDBY", fill="#00f0ff", font=("Segoe UI", 8, "bold"))
            
        elif self.scan_state == "scanning":
            # Scanning loader arcs
            self.canvas.create_arc(cx - 65, cy - 65, cx + 65, cy + 65, start=self.spinner_angle, extent=90, outline="#ff8800", width=5, style="arc")
            self.canvas.create_arc(cx - 65, cy - 65, cx + 65, cy + 65, start=self.spinner_angle + 180, extent=90, outline="#00f0ff", width=5, style="arc")
            
            # Pulsing radar signal
            self.canvas.create_oval(cx - self.pulse_radius, cy - self.pulse_radius, cx + self.pulse_radius, cy + self.pulse_radius, outline="#ff8800", width=2)
            self.canvas.create_text(cx, cy, text="ANALYZING", fill="#ff8800", font=("Segoe UI", 9, "bold"))
            
        elif self.scan_state == "safe":
            # Secure Shield Polygon
            shield_points = [
                cx, cy - 55,
                cx + 35, cy - 55,
                cx + 35, cy - 14,
                cx, cy + 22,
                cx - 35, cy - 14,
                cx - 35, cy - 55
            ]
            self.canvas.create_polygon(shield_points, fill="#0c2e1f", outline="#00ff66", width=3)
            # Checkmark symbol
            self.canvas.create_line(cx - 12, cy - 28, cx - 2, cy - 18, fill="#00ff66", width=4)
            self.canvas.create_line(cx - 2, cy - 18, cx + 14, cy - 38, fill="#00ff66", width=4)
            # "CLEAN" label sits inside the lower shield area, well above the arc
            self.canvas.create_text(cx, cy - 4, text="CLEAN", fill="#00ff66", font=("Segoe UI", 8, "bold"))
            
            # Render circular progress and risk labels
            self.draw_risk_score_visualization(cx, cy)
            
        elif self.scan_state == "malicious":
            # Threat Triangle Badge
            triangle_points = [
                cx, cy - 58,
                cx + 40, cy + 8,
                cx - 40, cy + 8
            ]
            self.canvas.create_polygon(triangle_points, fill="#3f0f15", outline="#ff003c", width=3)
            # Bold exclamation
            self.canvas.create_line(cx, cy - 40, cx, cy - 14, fill="#ff003c", width=4)
            self.canvas.create_oval(cx - 3, cy - 7, cx + 3, cy - 1, fill="#ff003c", outline="#ff003c", width=2)
            # "THREAT" label inside lower triangle area, well above the arc
            self.canvas.create_text(cx, cy + 0, text="THREAT", fill="#ff003c", font=("Segoe UI", 8, "bold"))
            
            # Render circular progress and risk labels
            self.draw_risk_score_visualization(cx, cy)
            
    def draw_risk_score_visualization(self, cx, cy):
        """
        Draws the circular progress bar track, active color-coded progress arc,
        numerical risk score percentage, and risk classification text.
        Labels are placed BELOW the arc ring (outside it) to prevent overlap.
        """
        # 1. Circular progress track ring
        self.canvas.create_arc(cx - 70, cy - 70, cx + 70, cy + 70, start=90, extent=-360, fill="", outline="#1f293d", width=6, style="arc")
        
        # 2. Color and label from current animated score
        color, label = self.get_risk_properties(self.current_risk_score)
        extent_angle = -3.6 * self.current_risk_score
        
        # 3. Active progress arc
        self.canvas.create_arc(cx - 70, cy - 70, cx + 70, cy + 70, start=90, extent=extent_angle, fill="", outline=color, width=6, style="arc")
        
        # 4. Score text placed BELOW the ring (arc bottom edge is at cy+70)
        #    cy+80 and cy+93 are safely outside the ring
        self.canvas.create_text(cx, cy + 80, text=f"RISK: {int(self.current_risk_score)}%", fill=color, font=("Segoe UI", 9, "bold"))
        self.canvas.create_text(cx, cy + 93, text=label, fill=color, font=("Segoe UI", 8, "bold"))
            
    def start_dashboard_background_loop(self):
        def loop():
            # Update visual dial position
            self.spinner_angle = (self.spinner_angle + 6) % 360
            
            # Pulse logic for scanner
            if self.pulse_grow:
                self.pulse_radius += 1.5
                if self.pulse_radius >= 55:
                    self.pulse_grow = False
            else:
                self.pulse_radius -= 1.5
                if self.pulse_radius <= 25:
                    self.pulse_grow = True
                    
            self.draw_status_shield()
            # Loop at roughly ~30fps
            self.root.after(33, loop)
        loop()

    # ----------------------------------------------------
    # API AND THREADING LOGIC
    # ----------------------------------------------------
    def start_scan_thread(self):
        url = self.url_entry.get().strip()
        if not url or url in ("http://", "https://"):
            self.log_terminal("Scan request rejected: Target resource input is empty.", "error")
            self.status_lbl.config(text="ERROR: SPECIFY A URL", fg="#ff003c")
            return
            
        self.btn_scan.config(state="disabled")
        self.scan_state = "scanning"
        self.current_risk_score = 0
        self.status_lbl.config(text="SCANNING VT DATABASES...", fg="#ff8800")
        self.log_terminal(f"Establishing API channel. Scanning host: {url}", "system")
        
        # Offload API request to secondary thread
        thread = threading.Thread(target=self.scan_site_worker, args=(url,), daemon=True)
        thread.start()
        
    def scan_site_worker(self, url):
        # Extract domain, run DNS & WHOIS Intelligence checks asynchronously
        domain = extract_domain(url)
        dns_data = self.resolve_dns_records(domain)
        whois_data = self.get_whois_info(domain)
        
        # Detect if we should use local simulation mode (no API key configured or fallback key used)
        use_simulation = (
            self.api_key == "YOUR_VIRUSTOTAL_API_KEY" or 
            not self.api_key or 
            self.api_key.strip() == "" or
            self.api_key == "b08753e41ef61863bd3a2e667cc093b41ca12b36232be34dfa352a39a9fec55"
        )
        
        if use_simulation:
            self.root.after(0, self.log_simulation_notice)
            self.run_heuristic_simulation(url, prefix="[HEURISTIC SIMULATION]", dns_data=dns_data, whois_data=whois_data)
            return
            
        params = {
            'apikey': self.api_key,
            'resource': url,
        }
        
        try:
            # Let the scan loader spin briefly to present the UI animation
            time.sleep(1.2)
            
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            
            if response.status_code == 204:
                self.root.after(0, self.on_scan_error, "Rate limit exceeded (Max 4 queries/min). Falling back to Heuristic Simulation...", "warning")
                self.run_heuristic_simulation(url, prefix="[API LIMIT FALLBACK]", dns_data=dns_data, whois_data=whois_data)
                return
            elif response.status_code == 403:
                self.root.after(0, self.log_api_key_instructions)
                self.root.after(0, self.on_scan_error, "API Access Denied (403). Falling back to Heuristic Simulation...", "warning")
                self.run_heuristic_simulation(url, prefix="[API Fallback Heuristics]", dns_data=dns_data, whois_data=whois_data)
                return
            elif response.status_code != 200:
                self.root.after(0, self.on_scan_error, f"API HTTP status {response.status_code}. Falling back to Heuristics...", "warning")
                self.run_heuristic_simulation(url, prefix="[API Fallback Heuristics]", dns_data=dns_data, whois_data=whois_data)
                return
                
            try:
                result = response.json()
            except ValueError:
                self.root.after(0, self.on_scan_error, "Decoder failed. Falling back to Heuristics...", "warning")
                self.run_heuristic_simulation(url, prefix="[API Fallback Heuristics]", dns_data=dns_data, whois_data=whois_data)
                return
                
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                if positives > 0:
                    score, metrics = self.compute_url_risk_metrics(url, vt_positives=positives, vt_total=total, is_threat=True)
                    self.root.after(0, self.on_scan_result, False, f"CRITICAL THREAT! Detected malicious flag on {positives}/{total} database checks.", url, score, metrics, dns_data, whois_data)
                else:
                    score, metrics = self.compute_url_risk_metrics(url, vt_positives=0, vt_total=total, is_threat=False)
                    self.root.after(0, self.on_scan_result, True, f"Scan completed. Clean resource. Verified safe on all {total} checks.", url, score, metrics, dns_data, whois_data)
            else:
                self.root.after(0, self.on_scan_error, "Target has no scan history. Submitting to VT and running heuristics...", "info")
                self.submit_url_for_scanning(url)
                self.run_heuristic_simulation(url, prefix="[LOCAL HEURISTIC]", dns_data=dns_data, whois_data=whois_data)
                
        except Exception as e:
            self.root.after(0, self.on_scan_error, f"Socket connection failed ({str(e)}). Running offline heuristics...", "warning")
            self.run_heuristic_simulation(url, prefix="[OFFLINE HEURISTIC]", dns_data=dns_data, whois_data=whois_data)

    def run_heuristic_simulation(self, url, prefix="[HEURISTIC SIMULATION]", dns_data=None, whois_data=None):
        # Let's perform a simple check
        time.sleep(1.0)
        is_malicious = any(term in url.lower() for term in ["malicious", "phishing", "virus", "dangerous", "evil", "hack", "block", "test-malicious"])
        
        score, metrics = self.compute_url_risk_metrics(url, vt_positives=0, vt_total=0, is_threat=is_malicious)
        
        if dns_data is None:
            domain = extract_domain(url)
            dns_data = self.resolve_dns_records(domain)
            
        if whois_data is None:
            domain = extract_domain(url)
            whois_data = self.get_whois_info(domain)
            
        if is_malicious:
            self.root.after(0, self.on_scan_result, False, f"{prefix} Threat flagged! Match found in offline database signature list.", url, score, metrics, dns_data, whois_data)
        else:
            self.root.after(0, self.on_scan_result, True, f"{prefix} Clear signature. No threats detected in offline heuristics database.", url, score, metrics, dns_data, whois_data)
            
    def log_simulation_notice(self):
        self.log_terminal("[SYS] Running in Heuristics Simulation Mode (API key is not configured in .env).", "system")

    def log_api_key_instructions(self):
        self.log_terminal("--------------------------------------------------", "info")
        self.log_terminal("VT API KEY IS INVALID OR EXPIRED.", "error")
        self.log_terminal("Please register for a free account at: www.virustotal.com", "info")
        self.log_terminal("And update the VT_API_KEY variable in your .env file.", "info")
        self.log_terminal("--------------------------------------------------", "info")

    def submit_url_for_scanning(self, url):
        try:
            params = {'apikey': self.api_key, 'url': url}
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    self.root.after(0, self.on_scan_error, "URL queued successfully! Re-scan in 60 seconds.", "success")
                else:
                    self.root.after(0, self.on_scan_error, "Failed to queue scan: " + result.get('verbose_msg', 'Service error'), "error")
            else:
                self.root.after(0, self.on_scan_error, f"Queue request failed: HTTP {response.status_code}", "error")
        except Exception as e:
            self.root.after(0, self.on_scan_error, f"Submit request error: {str(e)}", "error")
            
    def on_scan_error(self, msg, log_type):
        self.btn_scan.config(state="normal")
        self.scan_state = "idle"
        self.status_lbl.config(text="STANDBY // SCAN COMPLETED", fg="#9ca3af")
        self.log_terminal(msg, log_type)
        
    def analyze_redirects(self, start_url, max_redirects=6):
        """
        Actively follows HTTP redirects, detecting loop hazards and compiling status codes.
        """
        chain = []
        visited = set()
        current_url = start_url
        if not current_url.startswith(("http://", "https://")):
            current_url = "http://" + current_url
            
        loop_detected = False
        limit_exceeded = False
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        for _ in range(max_redirects):
            if current_url in visited:
                loop_detected = True
                break
            visited.add(current_url)
            
            try:
                # Use headers only request with allow_redirects=False to intercept redirects manually
                response = requests.head(current_url, headers=headers, timeout=3.0, allow_redirects=False)
                
                # Check for redirection status code
                if response.status_code in (301, 302, 303, 307, 308):
                    next_url = response.headers.get('Location')
                    if not next_url:
                        break
                    
                    # Resolve relative URLs
                    from urllib.parse import urljoin
                    next_url = urljoin(current_url, next_url)
                    
                    chain.append((current_url, response.status_code, next_url))
                    current_url = next_url
                else:
                    break
            except Exception:
                # Capture connection breakdowns cleanly
                chain.append((current_url, "ERR_CONN", None))
                break
        else:
            limit_exceeded = True
            
        final_destination = current_url
        return {
            'chain': chain,
            'count': len(chain),
            'final_destination': final_destination,
            'loop_detected': loop_detected,
            'limit_exceeded': limit_exceeded
        }

    def resolve_dns_records(self, domain):
        """
        Actively queries standard DNS records (A, AAAA, MX, NS, TXT, CNAME)
        using dnspython, returning lists of records and query timing metrics.
        """
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'response_time_ms': 0,
            'timeout_occurred': False
        }
        
        # Configure dnspython resolver parameters (3.0s query limit)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 3.0
        
        start_time = time.time()
        
        for rdtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = resolver.resolve(domain, rdtype)
                for rdata in answers:
                    if rdtype == 'MX':
                        records[rdtype].append(f"{rdata.exchange.to_text().rstrip('.')} (preference={rdata.preference})")
                    elif rdtype == 'CNAME':
                        records[rdtype].append(rdata.target.to_text().rstrip('.'))
                    else:
                        records[rdtype].append(rdata.to_text())
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                # Target domain is invalid or doesn't exist, stop queries
                break
            except dns.exception.Timeout:
                records['timeout_occurred'] = True
            except Exception:
                pass
                
        end_time = time.time()
        records['response_time_ms'] = int((end_time - start_time) * 1000)
        return records

    def analyze_ssl(self, hostname, port=443, timeout=3.0):
        """
        Actively checks HTTPS availability and parses SSL certificate details.
        Checks for expired, self-signed certificates, or hostname mismatches.
        """
        import socket
        import ssl
        
        ssl_info = {
            'https_available': False,
            'issuer': 'N/A',
            'subject': 'N/A',
            'valid_from': 'N/A',
            'valid_until': 'N/A',
            'days_remaining': 0,
            'expired': False,
            'self_signed': False,
            'hostname_mismatch': False,
            'ssl_status': 'Critical',
            'error_msg': None
        }
        
        # Setup TCP socket and wrapping context
        context = ssl.create_default_context()
        
        cert = None
        # Try a verifying connection first
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            conn = context.wrap_socket(sock, server_hostname=hostname)
            conn.connect((hostname, port))
            cert = conn.getpeercert()
            ssl_info['https_available'] = True
            ssl_info['ssl_status'] = 'Secure'
            conn.close()
        except ssl.SSLCertVerificationError as e:
            # Verification failed! Analyze certificate details using unverified context
            ssl_info['https_available'] = True
            ssl_info['ssl_status'] = 'Critical'
            
            err_str = str(e)
            if "hostname" in err_str.lower() or "match" in err_str.lower():
                ssl_info['hostname_mismatch'] = True
            elif "self-signed" in err_str.lower() or "self signed" in err_str.lower() or "local issuer" in err_str.lower():
                ssl_info['self_signed'] = True
                
            try:
                unv_context = ssl._create_unverified_context()
                unv_context.check_hostname = False
                unv_context.verify_mode = ssl.CERT_NONE
                
                sock_unv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_unv.settimeout(timeout)
                conn_unv = unv_context.wrap_socket(sock_unv, server_hostname=hostname)
                conn_unv.connect((hostname, port))
                cert = conn_unv.getpeercert()
                conn_unv.close()
            except Exception as ex:
                ssl_info['error_msg'] = f"Failed to fetch unverified cert: {str(ex)}"
        except Exception as e:
            ssl_info['https_available'] = False
            ssl_info['ssl_status'] = 'Critical'
            ssl_info['error_msg'] = str(e)
            return ssl_info
            
        if not cert:
            return ssl_info
            
        # Parse Issuer details
        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
        ssl_info['issuer'] = issuer_dict.get('commonName', issuer_dict.get('organizationName', 'Unknown Issuer'))
        
        # Parse Subject details
        subject_dict = dict(x[0] for x in cert.get('subject', []))
        ssl_info['subject'] = subject_dict.get('commonName', 'Unknown Subject')
        
        # Parse dates
        try:
            from ssl import cert_time_to_seconds
            from datetime import datetime, timezone
            valid_from_epoch = cert_time_to_seconds(cert.get('notBefore'))
            valid_until_epoch = cert_time_to_seconds(cert.get('notAfter'))
            
            dt_from = datetime.fromtimestamp(valid_from_epoch, timezone.utc)
            dt_until = datetime.fromtimestamp(valid_until_epoch, timezone.utc)
            
            ssl_info['valid_from'] = dt_from.strftime("%Y-%m-%d %H:%M:%S UTC")
            ssl_info['valid_until'] = dt_until.strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Days remaining
            now = datetime.now(timezone.utc)
            remaining = dt_until - now
            ssl_info['days_remaining'] = remaining.days
            
            if remaining.days <= 0:
                ssl_info['expired'] = True
                ssl_info['ssl_status'] = 'Critical'
            elif remaining.days < 30:
                if ssl_info['ssl_status'] == 'Secure':
                    ssl_info['ssl_status'] = 'Warning'
        except Exception as e:
            ssl_info['error_msg'] = f"Date parsing failed: {str(e)}"
            
        # If issuer match subject, it is self-signed
        if issuer_dict == subject_dict:
            ssl_info['self_signed'] = True
            
        # Check hostname mismatch fallback CN match
        cn = subject_dict.get('commonName', '').lower()
        if cn:
            if cn.startswith("*."):
                wildcard = cn[2:]
                parts_wild = wildcard.split('.')
                parts_host = hostname.lower().split('.')
                if len(parts_host) >= len(parts_wild):
                    end_match = '.'.join(parts_host[-len(parts_wild):]) == wildcard
                    if not end_match or len(parts_host) > len(parts_wild) + 1:
                        ssl_info['hostname_mismatch'] = True
                else:
                    ssl_info['hostname_mismatch'] = True
            elif hostname.lower() != cn:
                ssl_info['hostname_mismatch'] = True
                
        # Re-evaluate overall status
        if ssl_info['hostname_mismatch'] or ssl_info['expired'] or ssl_info['self_signed']:
            ssl_info['ssl_status'] = 'Critical'
        elif ssl_info['days_remaining'] < 30:
            ssl_info['ssl_status'] = 'Warning'
            
        return ssl_info

    def get_whois_info(self, domain):
        """
        Retrieves WHOIS registration details (Domain, Registrar, Dates, Country, Org, Status, NS)
        using python-whois. Caches repeated lookups locally.
        """
        if domain in self.whois_cache:
            return self.whois_cache[domain]
            
        try:
            # Query domain WHOIS
            w = whois.whois(domain)
            
            def format_date(d):
                if isinstance(d, list):
                    d = d[0]
                if isinstance(d, datetime):
                    return d.strftime("%Y-%m-%d %H:%M:%S")
                return str(d) if d else "N/A"
                
            def clean_list(val):
                if isinstance(val, list):
                    return ", ".join([str(v) for v in val if v])
                return str(val) if val else "N/A"
                
            info = {
                'domain_name': clean_list(w.domain_name).lower(),
                'registrar': clean_list(w.registrar),
                'creation_date': format_date(w.creation_date),
                'expiration_date': format_date(w.expiration_date),
                'updated_date': format_date(w.updated_date),
                'country': clean_list(w.country),
                'org': clean_list(w.org),
                'status': clean_list(w.status),
                'name_servers': clean_list(w.name_servers),
                'success': True
            }
        except Exception as e:
            info = {
                'success': False,
                'error_msg': str(e)
            }
            
        self.whois_cache[domain] = info
        return info

    def compute_url_risk_metrics(self, url, vt_positives=0, vt_total=0, is_threat=False):
        """
        Background-safe URL risk score and heuristics evaluator.
        """
        # 1. Run HTTP Redirect Analysis
        redirect_data = self.analyze_redirects(url)
        final_url = redirect_data['final_destination']
        
        metrics = {
            'https': False,
            'ssl_valid': False,
            'redirect_count': redirect_data['count'],
            'redirect_data': redirect_data,
            'blacklist_match': False,
            'vt_positives': vt_positives,
            'vt_total': vt_total,
            'is_threat': is_threat
        }
        
        # 2. Keyword blacklist heuristics (check original input and final URL)
        is_malicious_keyword = any(term in url.lower() or term in final_url.lower() 
                                   for term in ["malicious", "phishing", "virus", "dangerous", "evil", "hack", "block", "test-malicious"])
        metrics['blacklist_match'] = is_malicious_keyword
        if is_malicious_keyword:
            metrics['is_threat'] = True
            
        # 3. HTTPS scheme verification on final destination
        parsed = urlparse(final_url)
        if parsed.scheme.lower() == "https":
            metrics['https'] = True
            metrics['ssl_valid'] = True  # Default to true, verify below
            
        # 4. SSL certificate integrity check on final destination
        final_host = parsed.hostname or final_url
        ssl_data = self.analyze_ssl(final_host)
        metrics['ssl_data'] = ssl_data
        
        metrics['https'] = ssl_data['https_available']
        metrics['ssl_valid'] = ssl_data['https_available'] and ssl_data['ssl_status'] != 'Critical'
                
        # Calculate Risk Score (0-100)
        score = 0
        
        # - HTTPS usage (+15 if final URL is not HTTPS)
        if not metrics['https']:
            score += 15
            
        # - SSL Validity (+20 if HTTPS but SSL certificate invalid)
        if metrics['https'] and not metrics['ssl_valid']:
            score += 20
            
        # Increase risk score if: expired (+20), self-signed (+25), invalid hostname (+25)
        if ssl_data.get('expired'):
            score += 20
        if ssl_data.get('self_signed'):
            score += 25
        if ssl_data.get('hostname_mismatch'):
            score += 25
            
        # - Redirect metrics:
        # Base count redirects (+10 per hop, up to 30)
        score += min(30, metrics['redirect_count'] * 10)
        
        # Loop detected (+25 points)
        if redirect_data['loop_detected']:
            score += 25
        # Limit exceeded (+20 points)
        if redirect_data['limit_exceeded']:
            score += 20
        # If redirect count exceeds threshold of 2, add slight risk (+10)
        if metrics['redirect_count'] > 2:
            score += 10
        
        # - Blacklist matches (+35 points)
        if metrics['blacklist_match']:
            score += 35
            
        # - VirusTotal detections or offline threat status
        if vt_total > 0:
            if vt_positives > 0:
                ratio = vt_positives / vt_total
                vt_contribution = 40 + (ratio * 60)
                score += vt_contribution
        else:
            if metrics['is_threat']:
                score += 50
                
        # Cap score strictly between 0 and 100
        final_score = min(100, max(0, int(score)))
        return final_score, metrics


    def get_risk_properties(self, score):
        """
        Maps risk score to color codes and user-friendly risk level labels.
        """
        if score <= 20:
            return "#00ff66", "SAFE"         # Green
        elif score <= 40:
            return "#ffea00", "LOW RISK"     # Yellow
        elif score <= 60:
            return "#ff8800", "MEDIUM RISK"  # Orange
        elif score <= 80:
            return "#ff3c00", "HIGH RISK"    # Red-Orange
        else:
            return "#ff003c", "CRITICAL"     # Crimson Red

    def start_score_animation(self, target_score):
        """
        Initializes smooth score transition animation using TK after loops.
        """
        if hasattr(self, "_anim_task") and self._anim_task:
            self.root.after_cancel(self._anim_task)
            self._anim_task = None
        self.animate_step(target_score)
        
    def animate_step(self, target_score):
        """
        Exponential decay animation step to update current score dynamically.
        """
        diff = target_score - self.current_risk_score
        if abs(diff) < 0.5:
            self.current_risk_score = target_score
            self._anim_task = None
        else:
            step = diff * 0.15
            if abs(step) < 0.5:
                step = 0.5 if diff > 0 else -0.5
            self.current_risk_score += step
            self._anim_task = self.root.after(20, self.animate_step, target_score)

    def on_scan_result(self, is_safe, msg, url, score=0, metrics=None, dns_data=None, whois_data=None):
        self.btn_scan.config(state="normal")
        color, label = self.get_risk_properties(score)
        
        if is_safe:
            self.scan_state = "safe"
            self.status_lbl.config(text=f"SECURE - RISK SCORE: {score} ({label})", fg=color)
            self.log_terminal(msg, "success")
        else:
            self.scan_state = "malicious"
            self.status_lbl.config(text=f"THREAT - RISK SCORE: {score} ({label})", fg=color)
            self.log_terminal(msg, "warning")
            
            # Extract domain and update block entry
            domain = extract_domain(url)
            self.website_entry.delete(0, tk.END)
            self.website_entry.insert(0, domain)
            self.log_terminal(f"Pre-loaded domain for mitigation: {domain}", "info")
            
        # Log HTTP redirect chain
        if metrics and 'redirect_data' in metrics:
            rd = metrics['redirect_data']
            if rd['count'] > 0:
                self.log_terminal("HTTP Redirect Analysis Chain Detected:", "system")
                for src, code, dest in rd['chain']:
                    self.log_terminal(f"  * {src} -> [{code}] -> {dest}", "info" if code in (301, 302, 307, 308) else "warning")
                
                if rd['loop_detected']:
                    self.log_terminal("  [WARN] Redirection loop hazard identified!", "warning")
                if rd['limit_exceeded']:
                    self.log_terminal("  [WARN] Max redirection limit exceeded!", "warning")
                
                self.log_terminal(f"  * Final Destination: {rd['final_destination']}", "success" if metrics['https'] else "warning")
                
        # Log DNS Intelligence Report
        if dns_data:
            self.log_terminal(f"DNS Intelligence Report (Response Time: {dns_data.get('response_time_ms', 0)} ms):", "system")
            if dns_data.get('timeout_occurred'):
                self.log_terminal("  [WARNING] DNS queries encountered a timeout failure.", "warning")
                
            rdtypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            for rdtype in rdtypes:
                records_list = dns_data.get(rdtype, [])
                if records_list:
                    # Print first 5 records to avoid cluttering terminal logs
                    display_records = records_list[:5]
                    more_suffix = f" ... (+{len(records_list) - 5} more)" if len(records_list) > 5 else ""
                    self.log_terminal(f"  * {rdtype} Records: {display_records}{more_suffix}", "info")
                else:
                    self.log_terminal(f"  * {rdtype} Records: N/A", "info")
                    
        # Log WHOIS Intelligence Report
        if whois_data:
            if whois_data.get('success'):
                self.log_terminal("WHOIS Registry Intelligence Report:", "system")
                fields = [
                    ("Domain", 'domain_name'),
                    ("Registrar", 'registrar'),
                    ("Creation Date", 'creation_date'),
                    ("Expiry Date", 'expiration_date'),
                    ("Updated Date", 'updated_date'),
                    ("Country", 'country'),
                    ("Organization", 'org'),
                    ("Domain Status", 'status'),
                    ("Name Servers", 'name_servers')
                ]
                for key_label, key_field in fields:
                    self.log_terminal(f"  * {key_label}: {whois_data.get(key_field, 'N/A')}", "info")
            else:
                self.log_terminal("  [WARNING] WHOIS registry lookup query failed.", "warning")
                self.log_terminal(f"  Details: {whois_data.get('error_msg', 'Unknown Error')}", "info")
                
        # Log detailed risk breakdown
        if metrics:
            self.log_terminal(f"Website Risk Analysis Breakdown (Score: {score}/100):", "system")
            self.log_terminal(f"  * HTTPS Encrypted: {'Yes (0 pts)' if metrics['https'] else 'No (+15 pts)'}", "info" if metrics['https'] else "warning")
            if 'ssl_data' in metrics:
                sd = metrics['ssl_data']
                ssl_log_type = "success" if sd['ssl_status'] == "Secure" else ("warning" if sd['ssl_status'] == "Warning" else "error")
                self.log_terminal(f"  * SSL Status: {sd['ssl_status'].upper()}", ssl_log_type)
                if sd['https_available']:
                    self.log_terminal(f"    - Issuer: {sd['issuer']}", "info")
                    self.log_terminal(f"    - Subject: {sd['subject']}", "info")
                    self.log_terminal(f"    - Validity: {sd['valid_from']} to {sd['valid_until']}", "info")
                    self.log_terminal(f"    - Days Remaining: {sd['days_remaining']} days", "success" if sd['days_remaining'] > 30 else "warning")
                    
                    if sd['expired']:
                        self.log_terminal("    - [CAUTION] Certificate is EXPIRED (+20 pts)", "error")
                    if sd['self_signed']:
                        self.log_terminal("    - [CAUTION] Self-signed certificate detected (+25 pts)", "error")
                    if sd['hostname_mismatch']:
                        self.log_terminal("    - [CAUTION] Hostname Mismatch error (+25 pts)", "error")
            self.log_terminal(f"  * Redirection hops: {metrics['redirect_count']} (+{min(30, metrics['redirect_count'] * 10)} pts)", "info" if metrics['redirect_count'] == 0 else "warning")
            self.log_terminal(f"  * Keyword signature match: {'Yes (+35 pts)' if metrics['blacklist_match'] else 'No (0 pts)'}", "warning" if metrics['blacklist_match'] else "info")
            if metrics['vt_total'] > 0:
                self.log_terminal(f"  * VirusTotal detection: {metrics['vt_positives']}/{metrics['vt_total']} positive flags", "warning" if metrics['vt_positives'] > 0 else "info")
                
        # Log to SQLite
        if not is_safe or score > 60:
            status = "Malicious"
        elif score > 20:
            status = "Unknown"
        else:
            status = "Safe"
        self.db.log_scan(url, status, score)
        
        # Refresh real-time dashboard visual metrics
        self.refresh_dashboard_stats()
        
        # Start smooth animation of risk score
        self.start_score_animation(score)
        
    def refresh_dashboard_stats(self):
        """
        Retrieves scan statistics from SQLite database, updates key telemetry readouts,
        and redraws the embedded Matplotlib Donut Chart.
        """
        stats = self.db.get_statistics()
        
        # 1. Update text widgets
        self.val_total_scans.config(text=str(stats['total_scans']))
        self.val_total_blocked.config(text=str(stats['total_blocked']))
        self.val_total_malicious.config(text=str(stats['total_malicious']))
        self.val_todays_scans.config(text=str(stats['todays_scans']))
        self.val_last_scan.config(text=stats['last_scan'])
        
        # 2. Re-render Matplotlib pie chart
        self.ax.clear()
        
        counts = stats['pie_counts']
        labels = ['Safe', 'Malicious', 'Unknown']
        sizes = [counts['Safe'], counts['Malicious'], counts['Unknown']]
        colors = ['#00ff66', '#ff003c', '#00f0ff']
        
        # Filter zero-sized slices to keep chart neat
        filtered_labels = []
        filtered_sizes = []
        filtered_colors = []
        for l, s, c in zip(labels, sizes, colors):
            if s > 0:
                filtered_labels.append(l)
                filtered_sizes.append(s)
                filtered_colors.append(c)
                
        if not filtered_sizes:
            # Empty state placeholder donut ring
            self.ax.pie([1], labels=['NO DATA'], colors=['#1f293d'],
                        startangle=90, 
                        textprops={'color': '#6b7280', 'fontsize': 8, 'weight': 'bold'},
                        wedgeprops=dict(width=0.3, edgecolor='#121625'))
        else:
            # Draw donut ring — NO inline labels or pct (avoids all overlap)
            wedges, texts = self.ax.pie(
                filtered_sizes,
                labels=None,
                colors=filtered_colors,
                startangle=90,
                wedgeprops=dict(width=0.3, edgecolor='#121625')
            )
            # Build external legend entries: "Label  N%" placed outside the ring
            total = sum(filtered_sizes)
            legend_labels = [
                f"{lbl}  {sz/total*100:.0f}%"
                for lbl, sz in zip(filtered_labels, filtered_sizes)
            ]
            legend = self.ax.legend(
                wedges,
                legend_labels,
                loc='lower center',
                bbox_to_anchor=(0.5, -0.28),
                ncol=len(filtered_labels),
                frameon=False,
                fontsize=7,
                labelcolor='white',
                handlelength=1.0,
                handletextpad=0.4,
                columnspacing=0.8,
            )
            for text in legend.get_texts():
                text.set_color('#d1d5db')
                text.set_fontweight('bold')
            
        self.ax.axis('equal')
        self.fig.tight_layout()
        self.canvas_plot.draw()

    # ----------------------------------------------------
    # BLOCKER & HOST FILE MANIPULATION LOGIC
    # ----------------------------------------------------
    def block_website(self):
        website = self.website_entry.get().strip()
        pwd = self.password_entry.get()
        
        if not website:
            self.log_terminal("Filter update rejected: No domain specified.", "error")
            return
        if not pwd:
            self.log_terminal("Filter update rejected: Security password required.", "error")
            return
        if pwd != self.password:
            self.log_terminal("Access Denied: Invalid security password.", "error")
            return
            
        system_name = platform.system()
        if system_name == "Windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        elif system_name in ("Linux", "Darwin"):
            hosts_path = "/etc/hosts"
        else:
            self.log_terminal(f"Unsupported operating system: {system_name}", "error")
            return
            
        try:
            # Check if domain already blocked
            is_blocked = False
            if os.path.exists(hosts_path):
                with open(hosts_path, "r") as f:
                    for line in f:
                        if website in line and not line.strip().startswith("#"):
                            is_blocked = True
                            break
            if is_blocked:
                self.log_terminal(f"Resource is already active in blocking filter: {website}", "warning")
                return
                
            with open(hosts_path, "a") as hosts_file:
                hosts_file.write(f"\n127.0.0.1 {website}\n")
                hosts_file.write(f"127.0.0.1 www.{website}\n")
            self.log_terminal(f"Mitigation deployed. Block rule added for: {website}", "success")
            self.db.log_block(website)
            self.refresh_dashboard_stats()
        except PermissionError:
            self.log_permission_error(hosts_path)
        except Exception as e:
            self.log_terminal(f"Filter update error: {str(e)}", "error")
            
    def unblock_website(self):
        website = self.website_entry.get().strip()
        pwd = self.password_entry.get()
        
        if not website:
            self.log_terminal("Filter update rejected: No domain specified.", "error")
            return
        if not pwd:
            self.log_terminal("Filter update rejected: Security password required.", "error")
            return
        if pwd != self.password:
            self.log_terminal("Access Denied: Invalid security password.", "error")
            return
            
        system_name = platform.system()
        if system_name == "Windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        elif system_name in ("Linux", "Darwin"):
            hosts_path = "/etc/hosts"
        else:
            self.log_terminal(f"Unsupported operating system: {system_name}", "error")
            return
            
        try:
            if not os.path.exists(hosts_path):
                self.log_terminal(f"Hosts path not found: {hosts_path}", "error")
                return
                
            with open(hosts_path, "r") as hosts_file:
                lines = hosts_file.readlines()
                
            new_lines = []
            removed = False
            for line in lines:
                if website in line and not line.strip().startswith("#"):
                    removed = True
                    continue
                new_lines.append(line)
                
            if not removed:
                self.log_terminal(f"Resource was not registered in active blocker filter: {website}", "info")
                return
                
            with open(hosts_path, "w") as hosts_file:
                hosts_file.writelines(new_lines)
            self.log_terminal(f"Rule deprecated. Restored access to domain: {website}", "success")
            self.db.log_unblock(website)
            self.refresh_dashboard_stats()
        except PermissionError:
            self.log_permission_error(hosts_path)
        except Exception as e:
            self.log_terminal(f"Filter restoration error: {str(e)}", "error")
            
    def log_permission_error(self, path):
        self.log_terminal("CRITICAL ERROR: Insufficient File Permissions.", "error")
        self.log_terminal(f"Failed to access hosts file: {path}", "error")
        self.log_terminal("--------------------------------------------------", "info")
        self.log_terminal("STEPS TO RESOLVE ACCESS CONTROL PERMISSION ERROR:", "warning")
        if platform.system() == "Windows":
            self.log_terminal("1. Close the current application window.", "info")
            self.log_terminal("2. Search for CMD or PowerShell in Start Menu.", "info")
            self.log_terminal("3. Right-click, select 'Run as Administrator'.", "info")
            self.log_terminal("4. Run: python website_blocker.py", "info")
        else:
            self.log_terminal("1. Close the current application window.", "info")
            self.log_terminal("2. Relaunch the program using sudo elevation:", "info")
            self.log_terminal("   sudo python3 website_blocker.py", "info")
        self.log_terminal("--------------------------------------------------", "info")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityCommandCenterApp(root)
    root.mainloop()
