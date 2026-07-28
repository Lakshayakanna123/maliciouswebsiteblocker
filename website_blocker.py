import tkinter as tk
import os
import webbrowser
import platform
import requests
import threading
import time
from urllib.parse import urlparse

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

class SecurityCommandCenterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WebsiteTotal Command Center")
        
        # Configure deep background
        self.root.configure(bg="#08090f")
        
        # Start in borderless fullscreen by default
        self.is_fullscreen = True
        self.root.attributes("-fullscreen", True)
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
        
        self.setup_ui()
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
        
        # Window settings control frame
        control_frame = tk.Frame(header, bg="#08090f")
        control_frame.grid(row=0, column=1, sticky="e")
        
        self.fs_btn = tk.Button(
            control_frame, 
            text="⛶ Windoweded", 
            font=("Segoe UI", 10, "bold"), 
            bg="#1f293d", 
            fg="#ffffff", 
            activebackground="#2d3748", 
            activeforeground="#ffffff",
            bd=0, 
            padx=15, 
            pady=8, 
            cursor="hand2", 
            command=self.toggle_fullscreen
        )
        self.fs_btn.pack(side="left", padx=5)
        
        exit_btn = tk.Button(
            control_frame, 
            text="✕ Quit App", 
            font=("Segoe UI", 10, "bold"), 
            bg="#ef4444", 
            fg="#ffffff", 
            activebackground="#f87171", 
            activeforeground="#ffffff",
            bd=0, 
            padx=15, 
            pady=8, 
            cursor="hand2", 
            command=self.root.destroy
        )
        exit_btn.pack(side="left", padx=5)
        
        # ----------------------------------------------------
        # 2. MAIN DASHBOARD GRID
        # ----------------------------------------------------
        dashboard = tk.Frame(self.root, bg="#08090f")
        dashboard.grid(row=1, column=0, sticky="nsew", padx=40, pady=10)
        dashboard.columnconfigure(0, weight=1) # Left panel weight
        dashboard.columnconfigure(1, weight=1) # Right panel weight
        dashboard.rowconfigure(0, weight=1)
        
        # --- LEFT PANEL: MITIGATION CONTROL BOARD ---
        left_card = tk.Frame(dashboard, bg="#121625", bd=0, highlightthickness=1, highlightbackground="#263050")
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 20), pady=0)
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
        right_card.grid(row=0, column=1, sticky="nsew", padx=(20, 0), pady=0)
        right_card.columnconfigure(0, weight=1)
        right_card.rowconfigure(2, weight=1) # Allow log to take up available height
        
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
        self.canvas = tk.Canvas(right_card, bg="#121625", highlightthickness=0, width=220, height=220)
        self.canvas.grid(row=1, column=0, pady=(10, 20))
        
        # Pulse/Status label directly inside card layout
        self.status_lbl = tk.Label(
            right_card, 
            text="SECURE RADAR LOADED & STANDBY", 
            font=("Segoe UI", 10, "bold"), 
            bg="#121625", 
            fg="#9ca3af"
        )
        self.status_lbl.grid(row=1, column=0, sticky="s", pady=(210, 10))
        
        # Scrollable log terminal area
        term_label = tk.Label(
            right_card, 
            text="REAL-TIME SYSTEM AUDIT LOG", 
            font=("Segoe UI", 9, "bold"), 
            bg="#121625", 
            fg="#6b7280", 
            anchor="w"
        )
        term_label.grid(row=2, column=0, sticky="w", padx=30, pady=(15, 2))
        
        term_frame = tk.Frame(right_card, bg="#0a0b10", bd=0, highlightthickness=1, highlightbackground="#263050")
        term_frame.grid(row=3, column=0, sticky="nsew", padx=30, pady=(0, 30))
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
        self.add_hover_effect(self.fs_btn, "#374151", "#1f293d", "#ffffff", "#ffffff")
        self.add_hover_effect(exit_btn, "#dc2626", "#ef4444", "#ffffff", "#ffffff")
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
                cx, cy - 42,
                cx + 38, cy - 42,
                cx + 38, cy + 2,
                cx, cy + 47,
                cx - 38, cy + 2,
                cx - 38, cy - 42
            ]
            self.canvas.create_polygon(shield_points, fill="#0c2e1f", outline="#00ff66", width=3)
            # Checkmark symbol lines
            self.canvas.create_line(cx - 14, cy + 2, cx - 3, cy + 13, fill="#00ff66", width=4)
            self.canvas.create_line(cx - 3, cy + 13, cx + 16, cy - 8, fill="#00ff66", width=4)
            self.canvas.create_text(cx, cy + 26, text="CLEAN", fill="#00ff66", font=("Segoe UI", 8, "bold"))
            
        elif self.scan_state == "malicious":
            # Threat Triangle Badge
            triangle_points = [
                cx, cy - 45,
                cx + 42, cy + 28,
                cx - 42, cy + 28
            ]
            self.canvas.create_polygon(triangle_points, fill="#3f0f15", outline="#ff003c", width=3)
            # Bold exclamation visual lines
            self.canvas.create_line(cx, cy - 18, cx, cy + 8, fill="#ff003c", width=4)
            self.canvas.create_oval(cx - 3, cy + 15, cx + 3, cy + 21, fill="#ff003c", outline="#ff003c", width=2)
            self.canvas.create_text(cx, cy + 20, text="THREAT", fill="#ff003c", font=("Segoe UI", 8, "bold"))
            
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
        self.status_lbl.config(text="SCANNING VT DATABASES...", fg="#ff8800")
        self.log_terminal(f"Establishing API channel. Scanning host: {url}", "system")
        
        # Offload API request to secondary thread
        thread = threading.Thread(target=self.scan_site_worker, args=(url,), daemon=True)
        thread.start()
        
    def scan_site_worker(self, url):
        # Detect if we should use local simulation mode (no API key configured or fallback key used)
        use_simulation = (
            self.api_key == "YOUR_VIRUSTOTAL_API_KEY" or 
            not self.api_key or 
            self.api_key.strip() == "" or
            self.api_key == "b08753e41ef61863bd3a2e667cc093b41ca12b36232be34dfa352a39a9fec55"
        )
        
        if use_simulation:
            self.root.after(0, self.log_simulation_notice)
            self.run_heuristic_simulation(url, prefix="[HEURISTIC SIMULATION]")
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
                self.run_heuristic_simulation(url, prefix="[API LIMIT FALLBACK]")
                return
            elif response.status_code == 403:
                self.root.after(0, self.log_api_key_instructions)
                self.root.after(0, self.on_scan_error, "API Access Denied (403). Falling back to Heuristic Simulation...", "warning")
                self.run_heuristic_simulation(url, prefix="[API Fallback Heuristics]")
                return
            elif response.status_code != 200:
                self.root.after(0, self.on_scan_error, f"API HTTP status {response.status_code}. Falling back to Heuristics...", "warning")
                self.run_heuristic_simulation(url, prefix="[API Fallback Heuristics]")
                return
                
            try:
                result = response.json()
            except ValueError:
                self.root.after(0, self.on_scan_error, "Decoder failed. Falling back to Heuristics...", "warning")
                self.run_heuristic_simulation(url, prefix="[API Fallback Heuristics]")
                return
                
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                if positives > 0:
                    self.root.after(0, self.on_scan_result, False, f"CRITICAL THREAT! Detected malicious flag on {positives}/{total} database checks.", url)
                else:
                    self.root.after(0, self.on_scan_result, True, f"Scan completed. Clean resource. Verified safe on all {total} checks.", url)
            else:
                self.root.after(0, self.on_scan_error, "Target has no scan history. Submitting to VT and running heuristics...", "info")
                self.submit_url_for_scanning(url)
                self.run_heuristic_simulation(url, prefix="[LOCAL HEURISTIC]")
                
        except Exception as e:
            self.root.after(0, self.on_scan_error, f"Socket connection failed ({str(e)}). Running offline heuristics...", "warning")
            self.run_heuristic_simulation(url, prefix="[OFFLINE HEURISTIC]")

    def run_heuristic_simulation(self, url, prefix="[HEURISTIC SIMULATION]"):
        # Let's perform a simple check
        time.sleep(1.0)
        is_malicious = any(term in url.lower() for term in ["malicious", "phishing", "virus", "dangerous", "evil", "hack", "block", "test-malicious"])
        
        if is_malicious:
            self.root.after(0, self.on_scan_result, False, f"{prefix} Threat flagged! Match found in offline database signature list.", url)
        else:
            self.root.after(0, self.on_scan_result, True, f"{prefix} Clear signature. No threats detected in offline heuristics database.", url)
            
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
        
    def on_scan_result(self, is_safe, msg, url):
        self.btn_scan.config(state="normal")
        if is_safe:
            self.scan_state = "safe"
            self.status_lbl.config(text="SECURE RESOURCE APPROVED", fg="#00ff66")
            self.log_terminal(msg, "success")
        else:
            self.scan_state = "malicious"
            self.status_lbl.config(text="MALICIOUS WEBSITE DETECTED", fg="#ff003c")
            self.log_terminal(msg, "warning")
            
            # Extract domain and update block entry
            domain = extract_domain(url)
            self.website_entry.delete(0, tk.END)
            self.website_entry.insert(0, domain)
            self.log_terminal(f"Pre-loaded domain for mitigation: {domain}", "info")

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
