import tkinter as tk
from tkinter import messagebox
import os
import webbrowser
import platform
import requests

# Note: pkg_resources, subprocess, and filedialog were in the original import snippet but are unused.
# We comment them out to prevent ModuleNotFoundError on systems without setuptools/pkg_resources.
# import subprocess
# from tkinter import filedialog
# try:
#     import pkg_resources
# except ImportError:
#     pkg_resources = None

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

# Get settings from env or defaults
api_key = os.getenv("VT_API_KEY", "b08753e41ef61863bd3a2e667cc093b41ca12b36232be34dfa352a39a9fec55")
password = os.getenv("APP_PASSWORD", "admin")

# Window Setup
root = tk.Tk()
root.title("Antigravity Website Blocker & Malicious URL Scanner")
root.geometry("560x520")
root.resizable(False, False)

# Color Scheme & Aesthetics
BG_COLOR = "#0f0f1b"          # Deep cosmic dark background
CARD_BG = "#1b1b2f"           # Dark indigo card background
INPUT_BG = "#0d0d16"          # Ultra dark input boxes
TEXT_COLOR = "#e2e2ec"        # Light gray text
MUTED_TEXT = "#8a8aa3"        # Soft gray text
ACCENT_BLUE = "#5897fc"       # Neon blue highlight
ACCENT_GREEN = "#2ece7a"      # Emerald green for unblock/success
ACCENT_RED = "#f44b68"        # Crimson red for block/danger
ACCENT_ORANGE = "#ff9a4b"     # Amber orange for scan

# Tkinter Fonts
font_title = ("Segoe UI", 16, "bold")
font_label = ("Segoe UI", 10, "bold")
font_entry = ("Segoe UI", 10)
font_btn = ("Segoe UI", 10, "bold")
font_footer = ("Segoe UI", 8)

root.configure(bg=BG_COLOR)

# Header
header_frame = tk.Frame(root, bg=BG_COLOR)
header_frame.pack(fill="x", pady=(20, 10))

title_label = tk.Label(
    header_frame, 
    text="🛡️ Website Blocker & Scanner", 
    font=font_title, 
    bg=BG_COLOR, 
    fg=ACCENT_BLUE
)
title_label.pack()

subtitle_label = tk.Label(
    header_frame, 
    text="Secure your hosts file and scan URLs with VirusTotal API", 
    font=("Segoe UI", 9, "italic"), 
    bg=BG_COLOR, 
    fg=MUTED_TEXT
)
subtitle_label.pack(pady=(2, 0))

# Main Container Card
card = tk.Frame(root, bg=CARD_BG, bd=0, highlightthickness=1, highlightbackground="#2e2e4f")
card.pack(padx=25, pady=10, fill="both", expand=True)

# Grid Layout configuration
card.columnconfigure(0, weight=1)
card.columnconfigure(1, weight=3)

# Row 0: URL to Scan Entry
lbl_url = tk.Label(card, text="URL to Scan:", font=font_label, bg=CARD_BG, fg=TEXT_COLOR)
lbl_url.grid(row=0, column=0, sticky="w", padx=20, pady=(25, 10))

url_entry = tk.Entry(
    card, 
    font=font_entry, 
    bg=INPUT_BG, 
    fg=TEXT_COLOR, 
    insertbackground=TEXT_COLOR,
    bd=0, 
    highlightthickness=1, 
    highlightbackground="#3c3c5e",
    highlightcolor=ACCENT_BLUE
)
url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 20), pady=(25, 10), ipady=5)

# Row 1: Website to Block Entry
lbl_web = tk.Label(card, text="Website to Block:", font=font_label, bg=CARD_BG, fg=TEXT_COLOR)
lbl_web.grid(row=1, column=0, sticky="w", padx=20, pady=10)

website_entry = tk.Entry(
    card, 
    font=font_entry, 
    bg=INPUT_BG, 
    fg=TEXT_COLOR, 
    insertbackground=TEXT_COLOR,
    bd=0, 
    highlightthickness=1, 
    highlightbackground="#3c3c5e",
    highlightcolor=ACCENT_BLUE
)
website_entry.grid(row=1, column=1, sticky="ew", padx=(0, 20), pady=10, ipady=5)

# Row 2: Password Entry
lbl_pass = tk.Label(card, text="Password:", font=font_label, bg=CARD_BG, fg=TEXT_COLOR)
lbl_pass.grid(row=2, column=0, sticky="w", padx=20, pady=10)

password_entry = tk.Entry(
    card, 
    font=font_entry, 
    show="*", 
    bg=INPUT_BG, 
    fg=TEXT_COLOR, 
    insertbackground=TEXT_COLOR,
    bd=0, 
    highlightthickness=1, 
    highlightbackground="#3c3c5e",
    highlightcolor=ACCENT_BLUE
)
password_entry.grid(row=2, column=1, sticky="ew", padx=(0, 20), pady=10, ipady=5)

# Row 3: Action Buttons Frame
btn_frame = tk.Frame(card, bg=CARD_BG)
btn_frame.grid(row=3, column=0, columnspan=2, pady=(20, 20), padx=20, sticky="ew")

btn_frame.columnconfigure(0, weight=1)
btn_frame.columnconfigure(1, weight=1)
btn_frame.columnconfigure(2, weight=1)

# Helper function to check hosts permission warning
def show_permission_error():
    messagebox.showerror(
        "Administrator Rights Required", 
        "Failed to modify system hosts file.\n\nPlease run this script as Administrator (Windows) or root (macOS/Linux) to use Block/Unblock actions."
    )

# The Scanner Logic
def checksite():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Warning", "Please enter a website URL")
        return

    params = {
        'apikey': api_key,
        'resource': url,
    }

    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        
        # Check HTTP Status Codes before trying to parse JSON
        if response.status_code == 204:
            messagebox.showerror(
                "Rate Limit Exceeded", 
                "VirusTotal API rate limit exceeded (limit is 4 requests per minute for public API keys).\n\nPlease wait a minute and try again."
            )
            return
        elif response.status_code == 403:
            messagebox.showerror(
                "Invalid API Key", 
                "Access Forbidden (HTTP 403).\n\nPlease check if your VirusTotal API key in the .env file is correct and active."
            )
            return
        elif response.status_code != 200:
            messagebox.showerror(
                "API Error", 
                f"VirusTotal API returned HTTP status {response.status_code}.\n\nResponse: {response.text[:200]}"
            )
            return

        # Attempt to decode JSON response
        try:
            result = response.json()
        except ValueError:
            messagebox.showerror(
                "JSON Decode Error", 
                "Failed to parse response from VirusTotal as JSON.\n\nThe service might be experiencing issues."
            )
            return

        if result.get('response_code') == 1:
            positives = result.get('positives', 0)
            if positives > 0:
                messagebox.showwarning("Warning", f"This website is malicious!\n\nDetected by {positives} engines.")
                block_button.config(state="normal")
            else:
                messagebox.showinfo("Info", "This website is safe.")
                block_button.config(state="disabled")
        else:
            messagebox.showerror("Error", "An error occurred while checking the website. (Report not found or limit exceeded)")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect to VirusTotal API:\n{str(e)}")

# The Blocker Logic
def block_website():
    if website_entry.get() == "":
        messagebox.showerror("Error", "Please Enter a Website")
        return
    if password_entry.get() == "":
        messagebox.showerror("Error", "Please Enter a Password")
        return
    if password_entry.get() != password:
        messagebox.showerror("Error", "Please Enter a Valid Password")
        return
    else:
        # Define the websites you want to block
        websites_to_block = website_entry.get()

        # Determine the path of the hosts file based on the operating system
        system_name = platform.system()
        if system_name == "Windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        elif system_name == "Linux" or system_name == "Darwin": # macOS is a Unix-like system
            hosts_path = "/etc/hosts"
        else:
            messagebox.showerror("Error", "Unsupported operating system:" + system_name)
            return

        # Open the hosts file in append mode and add blocking rules
        try:
            with open(hosts_path, "a") as hosts_file:
                entry = "127.0.0.1 " + website_entry.get() + "\n"
                hosts_file.write(entry)
            messagebox.showinfo("Blocked", "Successfully Website Blocked")
        except PermissionError:
            show_permission_error()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

# The Unblocker Logic
def unblock_website():
    if website_entry.get() == "":
        messagebox.showerror("Error", "Please Enter a Website")
        return
    if password_entry.get() == "":
        messagebox.showerror("Error", "Please Enter a Password")
        return
    if password_entry.get() != password:
        messagebox.showerror("Error", "Please Enter a Valid Password")
        return
    else:
        # Define the websites you want to block
        websites_to_unblock = website_entry.get()

        # Determine the path of the hosts file based on the operating system
        system_name = platform.system()
        if system_name == "Windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        elif system_name == "Linux" or system_name == "Darwin": # macOS is a Unix-like system
            hosts_path = "/etc/hosts"
        else:
            messagebox.showerror("Error", "Unsupported operating system:" + system_name)
            return

        # Read the contents of the hosts file
        try:
            with open(hosts_path, "r") as hosts_file:
                lines = hosts_file.readlines()
        except PermissionError:
            show_permission_error()
            return
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while reading: {str(e)}")
            return

        # Remove the blocking rules from the hosts file
        try:
            with open(hosts_path, "w") as hosts_file:
                for line in lines:
                    should_remove = False
                    if website_entry.get() in line:
                        should_remove = True
                    if not should_remove:
                        hosts_file.write(line)
            messagebox.showinfo("Unblocked", "Successfully Website Unblocked")
        except PermissionError:
            show_permission_error()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while writing: {str(e)}")

# Buttons setup
scan_button = tk.Button(
    btn_frame, 
    text="🔍 Scan URL", 
    command=checksite, 
    font=font_btn, 
    bg=ACCENT_ORANGE, 
    fg="#0f0f1b", 
    activebackground="#ffa762",
    activeforeground="#0f0f1b",
    bd=0, 
    cursor="hand2"
)
scan_button.grid(row=0, column=0, padx=5, sticky="ew", ipady=8)

block_button = tk.Button(
    btn_frame, 
    text="🚫 Block Website", 
    command=block_website, 
    font=font_btn, 
    bg=ACCENT_RED, 
    fg=TEXT_COLOR, 
    activebackground="#ff5c7a",
    activeforeground=TEXT_COLOR,
    bd=0, 
    state="disabled",
    cursor="hand2"
)
block_button.grid(row=0, column=1, padx=5, sticky="ew", ipady=8)

unblock_button = tk.Button(
    btn_frame, 
    text="🔓 Unblock Website", 
    command=unblock_website, 
    font=font_btn, 
    bg=ACCENT_GREEN, 
    fg="#0f0f1b", 
    activebackground="#3ce28c",
    activeforeground="#0f0f1b",
    bd=0, 
    cursor="hand2"
)
unblock_button.grid(row=0, column=2, padx=5, sticky="ew", ipady=8)

# Hover effect helpers
def on_enter(e, color):
    if e.widget["state"] != "disabled":
        e.widget['background'] = color

def on_leave(e, color):
    if e.widget["state"] != "disabled":
        e.widget['background'] = color

scan_button.bind("<Enter>", lambda e: on_enter(e, "#ffa762"))
scan_button.bind("<Leave>", lambda e: on_leave(e, ACCENT_ORANGE))
block_button.bind("<Enter>", lambda e: on_enter(e, "#ff5c7a"))
block_button.bind("<Leave>", lambda e: on_leave(e, ACCENT_RED))
unblock_button.bind("<Enter>", lambda e: on_enter(e, "#3ce28c"))
unblock_button.bind("<Leave>", lambda e: on_leave(e, ACCENT_GREEN))

# Status info/help label at bottom of card
help_lbl = tk.Label(
    card,
    text="ℹ️ Scan a URL first. If it is malicious, you can Block it.",
    font=("Segoe UI", 9),
    bg=CARD_BG,
    fg=MUTED_TEXT
)
help_lbl.grid(row=4, column=0, columnspan=2, pady=(0, 20))

# Footer
footer = tk.Label(
    root, 
    text="Antigravity Secure Blocker v1.0", 
    font=font_footer, 
    bg=BG_COLOR, 
    fg=MUTED_TEXT
)
footer.pack(side="bottom", pady=15)

# The App Loop
root.mainloop()
