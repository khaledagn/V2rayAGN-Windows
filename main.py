import os
import sys
import ctypes

def check_privileges():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not check_privileges():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

if getattr(sys, 'frozen', False):
    run_as_admin()


import platform
import tkinter as tk
from tkinter import messagebox, PhotoImage, Entry, Button, Label, Toplevel, font, Scrollbar, filedialog, simpledialog
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
from PIL import Image, ImageTk
import subprocess
import pyperclip
import json
import ctypes
import winreg
import sqlite3
import time
import psutil
import base64
import webbrowser
import sys
import shutil

import json
import base64
import argparse
import re
from urllib.parse import urlparse
from urllib.parse import parse_qs
from urllib.parse import unquote




DEFAULT_PORT = 443
DEFAULT_SECURITY = "auto"
DEFAULT_LEVEL = 8
DEFAULT_NETWORK = "tcp"

TLS = "tls"
REALITY = "reality"
HTTP = "http"



if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))


if platform.architecture()[0] == '64bit':
    V2RAY_BINARY = os.path.join(base_path, 'core', 'v2ray64', 'v2ray.exe')
    CONFIG_PATH = os.path.join(base_path, 'core', 'v2ray64', 'config.json')
else:
    V2RAY_BINARY = os.path.join(base_path, 'core', 'v2ray32', 'v2ray.exe')
    CONFIG_PATH = os.path.join(base_path, 'core', 'v2ray32', 'config.json')

v2ray_process = None
db_original_path = os.path.join(base_path, "database", "profiles.db")
db_path = os.path.join(os.getenv('APPDATA'), "V2rayAGN", "profiles.db")
start_time = None
data_sent = 0
data_received = 0

def ensure_db():
    if not os.path.exists(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        shutil.copyfile(db_original_path, db_path)



# init db
def init_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS profiles 
                      (name TEXT PRIMARY KEY, config TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS state 
                      (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    conn.close()



# save profiles state
def save_state(key, value):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO state (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

# load profiles state
def load_state(key):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM state WHERE key=?", (key,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


# load available profiles
def load_profiles():
    profiles_combobox['values'] = []
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM profiles")
    profiles = [row[0] for row in cursor.fetchall()]
    profiles_combobox['values'] = profiles
    conn.close()


# load initial profile
def load_initial_profile():
    selected_profile = load_state('selected_profile')
    if selected_profile:
        profiles_combobox.set(selected_profile)
        load_profile()
    elif profiles_combobox['values']:
        profiles_combobox.current(0)
        load_profile()


# load profile after import
def load_profile(event=None):
    profile_name = profiles_combobox.get()
    if profile_name:
        profile_config = get_profile_config_from_db(profile_name)
        if profile_config:
            generate_v2ray_config(profile_config, profile_name)
            log(f"Profile '{profile_name}' loaded.", clear=True)
        else:
            messagebox.showerror("Error", "Profile configuration not found!")
    else:
        messagebox.showerror("Error", "No profile selected!")

# save a profile to db
def save_profile_to_db(name, config):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO profiles (name, config) VALUES (?, ?)", (name, config))
    conn.commit()
    conn.close()


# delete a profile
def delete_profile_from_db(name):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM profiles WHERE name=?", (name,))
    conn.commit()
    conn.close()

# get a profile config from db
def get_profile_config_from_db(name):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT config FROM profiles WHERE name=?", (name,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


# load selected profile in combobox
def load_selected_profile():
    profile_name = profiles_combobox.get()
    if profile_name:
        profile_config = get_profile_config_from_db(profile_name)
        if profile_config:
            log(f"Profile '{profile_name}' loaded.")
        else:
            messagebox.showerror("Error", "Profile configuration not found!")
    else:
        messagebox.showerror("Error", "No profile selected!")

# edit a profile 
def edit_profile():
    profile_name = profiles_combobox.get()
    if profile_name:
        profile_config = get_profile_config_from_db(profile_name)
        if profile_config:
            editor = Toplevel(app)
            editor.title(f"Edit Profile - {profile_name}")

            
            app_icon = ImageTk.PhotoImage(file=os.path.join(base_path, 'resources', 'img', 'app_icon.png'))
            editor.iconphoto(False, app_icon)

            editor.geometry("600x400")

           
            editor.grid_rowconfigure(0, weight=1)
            editor.grid_columnconfigure(0, weight=1)

            editor_text = ScrolledText(editor)
            editor_text.insert(tk.END, profile_config)
            editor_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

            def save_changes():
                new_config_json = editor_text.get(1.0, tk.END).strip()
                save_profile_to_db(profile_name, new_config_json)
                log(f"Profile '{profile_name}' updated.")
                editor.destroy()

            save_button = Button(editor, text="Save", command=save_changes)
            save_button.grid(row=1, column=0, pady=10)

        else:
            messagebox.showerror("Error", "Profile not found.")
    else:
        messagebox.showerror("Error", "No profile selected!")


# delete profile
def delete_profile():
    profile_name = profiles_combobox.get()
    if profile_name:
        delete_profile_from_db(profile_name)
        load_profiles()
        log(f"Profile '{profile_name}' deleted.")
    else:
        messagebox.showerror("Error", "No profile selected!")



# run v2ray link to json converter 
 

# import config from clipboard
def import_config_from_clipboard():
    try:
        url = pyperclip.paste()
        if any(url.startswith(prefix) for prefix in ["vmess://", "vless://", "trojan://", "ss://"]):
            config_json = generateConfig(url)
        else:
            try:
                config_json = json.loads(url)
                config_json = json.dumps(config_json, indent=4)  # Ensure it is properly formatted JSON
            except json.JSONDecodeError:
                log("Invalid configuration format.")
                messagebox.showerror("Error", "Invalid configuration format.")
                return None
        return config_json
    except Exception as e:
        return None


# import config from file
def import_config_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("V2Ray Config", "*.v2agn")])
    if file_path:
        try:
            with open(file_path, 'r') as file:
                data = file.read().strip()
                if any(data.startswith(prefix) for prefix in ["vmess://", "vless://", "trojan://", "ss://"]):
                    config_json = generateConfig(data)   
                    profile_name = os.path.splitext(os.path.basename(file_path))[0]
                    return config_json, profile_name
                else:
                    messagebox.showerror("Error", "Invalid V2Ray URL format in the file.")
                    return None, None
        except Exception as e:
            log(f"Error: {e}")
            messagebox.showerror("Error", "Failed to load configuration file.")
            return None, None
    return None, None

# remove unwanted parts in the imported conf
def remove_unwanted_parts(config):
    if 'dns' in config:
        del config['dns']
    if 'fakedns' in config:
        del config['fakedns']
    for inbound in config.get('inbounds', []):
        if 'sniffing' in inbound and 'destOverride' in inbound['sniffing']:
            inbound['sniffing']['destOverride'] = [item for item in inbound['sniffing']['destOverride'] if item != 'fakedns']
    return config


# generate v2ray conf
def generate_v2ray_config(config_json, profile_name):
    try:
        config = json.loads(config_json)
        config = remove_unwanted_parts(config)
        for inbound in config.get('inbounds', []):
            if inbound.get('protocol') == 'socks':
                inbound['port'] = 10808
            elif inbound.get('protocol') == 'http':
                inbound['port'] = 10809
        formatted_json = json.dumps(config, indent=4)
        save_profile_to_db(profile_name, formatted_json)
        load_profiles()
        if 'created and saved.' not in log_text.get("1.0", tk.END):
            log(f"Profile '{profile_name}' created and saved.")
    except Exception as e:
        None

# on import click
def on_import():
    dialog = tk.Toplevel(app)
    dialog.title("Import Config")
    app_icon = ImageTk.PhotoImage(file=os.path.join(base_path, 'resources', 'img', 'app_icon.png'))
    dialog.iconphoto(False, app_icon)
    dialog.geometry("400x300")

    def center_window(window):
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')
    
    center_window(dialog)
    
    frame = tk.Frame(dialog, padx=20, pady=20)
    frame.pack(expand=True, fill=tk.BOTH)

    label = Label(frame, text="Choose import method:", font=("Helvetica", 12))
    label.pack(pady=10)
    
    profile_name_label = Label(frame, text="Profile Name:", font=("Helvetica", 10))
    profile_name_label.pack(pady=5)
    
    profile_name_entry = Entry(frame, font=("Helvetica", 10))
    profile_name_entry.pack(pady=5)
    
    def from_clipboard():
        profile_name = profile_name_entry.get()
        if not profile_name:
            messagebox.showerror("Error", "Profile name cannot be empty.")
            return
        config_json = import_config_from_clipboard()
        if config_json:
            generate_v2ray_config(config_json, profile_name)
        dialog.destroy()
    
    def from_file():
        config_json, profile_name = import_config_from_file()
        if config_json:
            generate_v2ray_config(config_json, profile_name)
        dialog.destroy()
    
    btn_clipboard = Button(frame, text="Import from Clipboard", command=from_clipboard, font=("Helvetica", 10), padx=10, pady=5)
    btn_clipboard.pack(pady=5)
    separate = Label(frame, text="or:", font=("Helvetica", 10))
    separate.pack(pady=5)
    btn_file = Button(frame, text="Import from File", command=from_file, font=("Helvetica", 10), padx=10, pady=5)
    btn_file.pack(pady=5)
    
    dialog.transient(app)
    dialog.grab_set()
    app.wait_window(dialog)


# check if V2rayAGN directory exists
def ensure_v2rayagn_directory():
    documents_path = os.path.join(os.path.expanduser('~'), 'Documents')
    v2rayagn_path = os.path.join(documents_path, 'V2rayAGN')
    if not os.path.exists(v2rayagn_path):
        os.makedirs(v2rayagn_path)
    return v2rayagn_path

# check protocol in json config and export to the appropriate URL format
def config_to_url(config):
    config_dict = json.loads(config)
    for outbound in config_dict.get('outbounds', []):
        protocol = outbound.get('protocol')
        if protocol == 'vmess':
            return json_to_vmess(outbound)
        elif protocol == 'vless':
            return json_to_vless(outbound)
        elif protocol == 'trojan':
            return json_to_trojan(outbound)
        elif protocol == 'shadowsocks':
            return json_to_ss(outbound)
    raise ValueError("Unsupported config type")

# export Vmess JSON to URL
def json_to_vmess(outbound):
    client = outbound['settings']['vnext'][0]['users'][0]
    vmess_config = {
        "v": "2",
        "ps": client.get("email", ""),
        "add": outbound['settings']['vnext'][0]['address'],
        "port": outbound['settings']['vnext'][0]['port'],
        "id": client['id'],
        "aid": client.get("alterId", "0"),
        "net": outbound['streamSettings']['network'],
        "type": outbound['streamSettings'].get("wsSettings", {}).get("path", ""),
        "host": outbound['streamSettings'].get("wsSettings", {}).get("headers", {}).get("Host", ""),
        "tls": "tls" if outbound['streamSettings'].get("security") == "tls" else ""
    }
    vmess_json = json.dumps(vmess_config)
    vmess_url = "vmess://" + base64.urlsafe_b64encode(vmess_json.encode()).decode()
    return vmess_url

# export Vless JSON to URL
def json_to_vless(outbound):
    client = outbound['settings']['vnext'][0]['users'][0]
    vless_url = f"vless://{client['id']}@{outbound['settings']['vnext'][0]['address']}:{outbound['settings']['vnext'][0]['port']}?type={outbound['streamSettings']['network']}&security=tls&path={outbound['streamSettings'].get('wsSettings', {}).get('path', '')}&host={outbound['streamSettings'].get('wsSettings', {}).get('headers', {}).get('Host', '')}"
    return vless_url

# export Trojan JSON to URL
def json_to_trojan(outbound):
    client = outbound['settings']['servers'][0]
    trojan_url = f"trojan://{client['password']}@{outbound['settings']['servers'][0]['address']}:{outbound['settings']['servers'][0]['port']}"
    return trojan_url

# export Shadowsocks JSON to URL
def json_to_ss(outbound):
    client = outbound['settings']['servers'][0]
    method = client['method']
    password = client['password']
    ss_config = f"{method}:{password}@{client['address']}:{client['port']}"
    ss_url = "ss://" + base64.urlsafe_b64encode(ss_config.encode()).decode()
    return ss_url

# export config 
def export_profile():
    profile_name = profiles_combobox.get()
    if profile_name:
        profile_config = get_profile_config_from_db(profile_name)
        if profile_config:
            try:
                export_url = config_to_url(profile_config)
                
                export_dialog = Toplevel(app)
                export_dialog.title("Export Profile")

                export_dialog.iconphoto(False, app_icon)

                export_dialog.geometry("200x150")
                def center_window(window):
                    window.update_idletasks()
                    width = window.winfo_width()
                    height = window.winfo_height()
                    x = (window.winfo_screenwidth() // 2) - (width // 2)
                    y = (window.winfo_screenheight() // 2) - (height // 2)
                    window.geometry(f'{width}x{height}+{x}+{y}')
        
                center_window(export_dialog)
                Label(export_dialog, text="Enter filename (without extension):").pack(pady=20)
                export_filename_entry = Entry(export_dialog)
                export_filename_entry.pack(pady=10)

                def on_export():
                    export_filename = export_filename_entry.get()
                    if export_filename:
                        v2rayagn_directory = ensure_v2rayagn_directory()
                        export_path = os.path.join(v2rayagn_directory, f"{export_filename}.v2agn")

                        with open(export_path, 'w') as file:
                            file.write(export_url)
                        messagebox.showinfo("Export Success", f"Configuration exported to {export_path}")
                        pyperclip.copy(export_url)
                        export_dialog.destroy()
                    else:
                        messagebox.showerror("Error", "Export filename cannot be empty.")

                export_button = Button(export_dialog, text="Export", command=on_export)
                export_button.pack(pady=10)

                export_dialog.transient(app)
                export_dialog.grab_set()
                app.wait_window(export_dialog)

            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Profile configuration not found.")
    else:
        messagebox.showerror("Error", "No profile selected!")

        
# start / stop toggle
def toggle_v2ray():
    global v2ray_process
    if v2ray_process is None:
        start_v2ray()
    else:
        stop_v2ray()


def kill_process_using_ports(ports):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port in ports and conn.pid == proc.pid:
                    proc.kill()
                    log(f"Killed process {proc.pid} ({proc.name()}) using port {conn.laddr.port}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# start v2ray
def start_v2ray():
    global v2ray_process, start_time, data_sent, data_received
    kill_process_using_ports([10809, 10808])
    selected_profile = profiles_combobox.get()
    if selected_profile:
        profile_config = get_profile_config_from_db(selected_profile)
        if profile_config:
            with open(CONFIG_PATH, 'w') as file:
                file.write(profile_config)
            v2ray_process = subprocess.Popen(
                [V2RAY_BINARY, "-config", CONFIG_PATH],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            set_system_proxy("127.0.0.1:10809")
            start_stop_button.config(text="Stop V2Ray", image=stop_icon)

            stats_frame.grid()
            
            start_time = time.time()
            net_io = psutil.net_io_counters()
            data_sent = net_io.bytes_sent
            data_received = net_io.bytes_recv

            update_statistics()

            footer.config(state=tk.NORMAL)
            footer.delete(1.0, tk.END)
            footer.insert(tk.END, "HTTP Proxy: ")
            footer.insert(tk.END, "127.0.0.1:10809", "set")
            footer.insert(tk.END, " Socks: ")
            footer.insert(tk.END, "127.0.0.1:10808", "set")
            footer.insert(tk.END, " | © 2024 by Khaled AGN")

            footer.tag_configure("set", foreground="green")
            footer.tag_configure("center", justify='center')
            footer.tag_add("center", "1.0", "end")
            footer.config(state=tk.DISABLED)

            log("V2Ray started.")
            save_state('selected_profile', selected_profile)

        else:
            messagebox.showerror("Error", "Profile configuration not found!")
    else:
        messagebox.showerror("Error", "No profile selected!")


# stop v2ray
def stop_v2ray():
    global v2ray_process
    if v2ray_process:
        v2ray_process.terminate()
        v2ray_process = None
        clear_system_proxy()
        start_stop_button.config(text="Start V2Ray", image=start_icon)

        stats_frame.grid_remove()

        footer.config(state=tk.NORMAL)
        footer.delete(1.0, tk.END)
        footer.insert(tk.END, "HTTP/Socks Proxy: ")
        footer.insert(tk.END, "Not Set", "not_set")
        footer.insert(tk.END, " | © 2024 by Khaled AGN")
        footer.tag_configure("not_set", foreground="red")
        footer.tag_configure("center", justify='center')
        footer.tag_add("center", "1.0", "end")
        footer.config(state=tk.DISABLED)

        log("V2Ray stopped and system proxy cleared.")


# set windows proxy settings
def set_system_proxy(proxy_address):
    try:
        key = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(reg_key, 'ProxyServer', 0, winreg.REG_SZ, proxy_address)
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  
        log("System proxy set.")
    except Exception as e:
        log(f"Error setting system proxy: {e}")


# clear windows proxy settings
def clear_system_proxy():
    try:
        key = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            winreg.DeleteValue(reg_key, 'ProxyServer')
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0) 
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  
        log("System proxy cleared.")
    except Exception as e:
        log(f"Error clearing system proxy: {e}")


# logs
def log(message, clear=False):
    log_text.config(state=tk.NORMAL)
    if clear:
        log_text.delete(1.0, tk.END)
    log_text.insert(tk.END, f"{message}\n")
    log_text.config(state=tk.DISABLED)
    log_text.yview(tk.END)


# udpate connection statistics
def update_statistics():
    global start_time, data_sent, data_received
    
    
    if start_time:
        duration = int(time.time() - start_time)
        duration_label.config(text=f"{duration} s")
    
    
    net_io = psutil.net_io_counters()
    
    
    data_sent_now = net_io.bytes_sent
    data_received_now = net_io.bytes_recv
    
    sent_mb = (data_sent_now - data_sent) / (1024 * 1024)
    received_mb = (data_received_now - data_received) / (1024 * 1024)
    
    data_usage_label.config(text=f"{sent_mb + received_mb:.2f} MB")
    
    
    speed = (data_sent_now - data_sent + data_received_now - data_received) / 1024
    speed_label.config(text=f"{speed:.2f} KB/s")
    
    
    data_sent = data_sent_now
    data_received = data_received_now
    
    
    app.after(1000, update_statistics)


# center main window
def center_window(window):
    window.update_idletasks()
    width = 900
    height = 480
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')

# resize icons
def resize_icon(path, size=(24, 24)):
    img = Image.open(path)
    img = img.resize(size, Image.LANCZOS)
    return ImageTk.PhotoImage(img)

# open links in browser
def open_link(url):
    webbrowser.open_new(url)




#v2ray generator
class EConfigType:
    class VMESS:
        protocolScheme = "vmess://"
        protocolName = "vmess"

    class CUSTOM:
        protocolScheme = ""
        protocolName = ""

    class SHADOWSOCKS:
        protocolScheme = "ss://"
        protocolName = "ss"

    class SOCKS:
        protocolScheme = "socks://"
        protocolName = "socks"

    class VLESS:
        protocolScheme = "vless://"
        protocolName = "vless"

    class TROJAN:
        protocolScheme = "trojan://"
        protocolName = "trojan"

    class WIREGUARD:
        protocolScheme = "wireguard://"
        protocolName = "wireguard"

    class FREEDOM:
        protocolScheme = "freedom://"
        protocolName = "freedom"

    class BLACKHOLE:
        protocolScheme = "blackhole://"
        protocolName = "blackhole"


class DomainStrategy:
    AsIs = "AsIs"
    UseIp = "UseIp"
    IpIfNonMatch = "IpIfNonMatch"
    IpOnDemand = "IpOnDemand"


class Fingerprint:
    randomized = "randomized"
    randomizedalpn = "randomizedalpn"
    randomizednoalpn = "randomizednoalpn"
    firefox_auto = "firefox_auto"
    chrome_auto = "chrome_auto"
    ios_auto = "ios_auto"
    android_11_okhttp = "android_11_okhttp"
    edge_auto = "edge_auto"
    safari_auto = "safari_auto"
    _360_auto = "360_auto"
    qq_auto = "qq_auto"


class LogBean:
    access: str
    error: str
    loglevel: str
    dnsLog: bool

    def __init__(self, access: str, error: str, loglevel: str, dnsLog: bool) -> None:
        self.access = access
        self.error = error
        self.loglevel = loglevel
        self.dnsLog = dnsLog


 
class InboundBean:
    class SniffingBean:
        enabled: bool
        destOverride: list[str]  # str
        metadataOnly: bool

        def __init__(
            self, enabled: bool, destOverride: list[str], metadataOnly: bool
        ) -> None:
            self.enabled = enabled
            self.destOverride = destOverride
            self.metadataOnly = metadataOnly

        def to_dict(self):
            return {
                "enabled": self.enabled,
                "destOverride": self.destOverride,
                "metadataOnly": self.metadataOnly,
            }

    class InSettingsBean:
        auth: str = None
        udp: bool = None
        userLevel: int = None
        address: str = None
        port: int = None
        network: str = None

        def __init__(
            self,
            auth: str = None,
            udp: bool = None,
            userLevel: int = None,
            address: str = None,
            port: int = None,
            network: str = None,
        ) -> None:
            self.auth = auth
            self.udp = udp
            self.userLevel = userLevel
            self.address = address
            self.port = port
            self.network = network

        def to_dict(self):
            return {
                "auth": self.auth,
                "udp": self.udp,
                "userLevel": self.userLevel,
                "address": self.address,
                "port": self.port,
                "network": self.network,
            }

    tag: str
    port: int
    protocol: str
    listen: str
    settings: any
    sniffing: SniffingBean
    streamSettings: any
    allocate: any

    def __init__(
        self,
        tag: str,
        port: int,
        protocol: str,
        listen: str,
        settings: any,
        sniffing: SniffingBean = None,
        streamSettings: any = None,
        allocate: any = None,
    ) -> None:
        self.tag = tag
        self.port = port
        self.protocol = protocol
        self.listen = listen
        self.settings = settings
        self.sniffing = sniffing
        self.streamSettings = streamSettings
        self.allocate = allocate

    def to_dict(self):
        return {
            "tag": self.tag,
            "port": self.port,
            "protocol": self.protocol,
            "listen": self.listen,
            "settings": self.settings.to_dict(),
            "sniffing": self.sniffing.to_dict() if self.sniffing else None,
            "streamSettings": self.streamSettings,
            "allocate": self.allocate,
        }


class OutboundBean:
    class OutSettingsBean:
        class VnextBean:
            class UsersBean:
                id: str = ""
                alterId: int = None
                security: str = DEFAULT_SECURITY
                level: int = DEFAULT_LEVEL
                encryption: str = ""
                flow: str = ""

                def __init__(
                    self,
                    id: str = "",
                    alterId: int = None,
                    security: str = DEFAULT_SECURITY,
                    level: int = DEFAULT_LEVEL,
                    encryption: str = "",
                    flow: str = "",
                ) -> None:
                    self.id = id
                    self.alterId = alterId
                    self.security = security
                    self.level = level
                    self.encryption = encryption
                    self.flow = flow

            address: str = ""
            port: int = DEFAULT_PORT
            users: list[UsersBean]  # UsersBean

            def __init__(
                self,
                address: str = "",
                port: int = DEFAULT_PORT,
                users: list[UsersBean] = [],
            ) -> None:
                self.address = address
                self.port = port
                self.users = users

        class ServersBean:
            class SocksUsersBean:
                user: str = ""
                # @SerializedName("pass")
                _pass: str = ""
                level: int = DEFAULT_LEVEL

                def __init__(
                    self, user: str = "", _pass: str = "", level: int = DEFAULT_LEVEL
                ) -> None:
                    self.user = user
                    self._pass = _pass
                    self.level = level

            address: str = ""
            method: str = "chacha20-poly1305"
            ota: bool = False
            password: str = ""
            port: int = DEFAULT_PORT
            level: int = DEFAULT_LEVEL
            email: str = None
            flow: str = None
            ivCheck: bool = None
            users: list[SocksUsersBean] = None  # SocksUsersBean

            def __init__(
                self,
                address: str = "",
                method: str = "chacha20-poly1305",
                ota: bool = False,
                password: str = "",
                port: int = DEFAULT_PORT,
                level: int = DEFAULT_LEVEL,
                email: str = None,
                flow: str = None,
                ivCheck: bool = None,
                users: list[SocksUsersBean] = None,
            ) -> None:
                self.address = address
                self.method = method
                self.ota = ota
                self.password = password
                self.port = port
                self.level = level
                self.email = email
                self.flow = flow
                self.ivCheck = ivCheck
                self.users = users

        class Response:
            type: str

            def __init__(self, type: str) -> None:
                self.type = type

        class WireGuardBean:
            publicKey: str = ""
            endpoint: str = ""

            def __init__(self, publicKey: str = "", endpoint: str = "") -> None:
                self.publicKey = publicKey
                self.endpoint = endpoint

        vnext: list[VnextBean] = None  # VnextBean
        servers: list[ServersBean] = None  # ServersBean
        response: Response = None
        network: str = None
        address: str = None
        port: int = None
        domainStrategy: str = None
        redirect: str = None
        userLevel: int = None
        inboundTag: str = None
        secretKey: str = None
        peers: list[WireGuardBean] = None  # WireGuardBean

        def __init__(
            self,
            vnext: list[VnextBean] = None,
            servers: list[ServersBean] = None,
            response: Response = None,
            network: str = None,
            address: str = None,
            port: int = None,
            domainStrategy: str = None,
            redirect: str = None,
            userLevel: int = None,
            inboundTag: str = None,
            secretKey: str = None,
            peers: list[WireGuardBean] = None,
        ) -> None:
            self.vnext = vnext
            self.servers = servers
            self.response = response
            self.network = network
            self.address = address
            self.port = port
            self.domainStrategy = domainStrategy
            self.redirect = redirect
            self.userLevel = userLevel
            self.inboundTag = inboundTag
            self.secretKey = secretKey
            self.peers = peers

    class StreamSettingsBean:
        class TcpSettingsBean:
            class HeaderBean:
                class RequestBean:
                    class HeadersBean:
                        Host: list[str] = []  # str
                        # @SerializedName("User-Agent")
                        userAgent: list[str] = None  # str
                        # @SerializedName("Accept-Encoding")
                        acceptEncoding: list[str] = None  # str
                        Connection: list[str] = None  # str
                        Pragma: str = None

                        def __init__(
                            self,
                            Host: list[str] = [],
                            userAgent: list[str] = None,
                            acceptEncoding: list[str] = None,
                            Connection: list[str] = None,
                            Pragma: str = None,
                        ) -> None:
                            self.Host = Host
                            self.userAgent = userAgent
                            self.acceptEncoding = acceptEncoding
                            self.Connection = Connection
                            self.Pragma = Pragma

                    path: list[str] = []  # str
                    headers: HeadersBean = HeadersBean()
                    version: str = None
                    method: str = None

                    def __init__(
                        self,
                        path: list[str] = [],
                        headers: HeadersBean = HeadersBean(),
                        version: str = None,
                        method: str = None,
                    ) -> None:
                        self.path = path
                        self.headers = headers
                        self.version = version
                        self.method = method

                type: str = "none"
                request: RequestBean = None

                def __init__(
                    self, type: str = "none", request: RequestBean = None
                ) -> None:
                    self.type = type
                    self.request = request

            header: HeaderBean = HeaderBean()
            acceptProxyProtocol: bool = None

            def __init__(
                self,
                header: HeaderBean = HeaderBean(),
                acceptProxyProtocol: bool = None,
            ) -> None:
                self.header = header
                self.acceptProxyProtocol = acceptProxyProtocol

        class KcpSettingsBean:
            class HeaderBean:
                type: str = "none"

                def __init__(self, type: str = "none") -> None:
                    self.type = type

            mtu: int = 1350
            tti: int = 50
            uplinkCapacity: int = 12
            downlinkCapacity: int = 100
            congestion: bool = False
            readBufferSize: int = 1
            writeBufferSize: int = 1
            header: HeaderBean = HeaderBean()
            seed: str = None

            def __init__(
                self,
                mtu: int = 1350,
                tti: int = 50,
                uplinkCapacity: int = 12,
                downlinkCapacity: int = 100,
                congestion: bool = False,
                readBufferSize: int = 1,
                writeBufferSize: int = 1,
                header: HeaderBean = HeaderBean(),
                seed: str = None,
            ) -> None:
                self.mtu = mtu
                self.tti = tti
                self.uplinkCapacity = uplinkCapacity
                self.downlinkCapacity = downlinkCapacity
                self.congestion = congestion
                self.readBufferSize = readBufferSize
                self.writeBufferSize = writeBufferSize
                self.header = header
                self.seed = seed

        class WsSettingsBean:
            class HeadersBean:
                Host: str = ""

                def __init__(self, Host: str = "") -> None:
                    self.Host = Host

            path: str = ""
            headers: HeadersBean = HeadersBean()
            maxEarlyData: int = None
            useBrowserForwarding: bool = None
            acceptProxyProtocol: bool = None

            def __init__(
                self,
                path: str = "",
                headers: HeadersBean = HeadersBean(),
                maxEarlyData: int = None,
                useBrowserForwarding: bool = None,
                acceptProxyProtocol: bool = None,
            ) -> None:
                self.path = path
                self.headers = headers
                self.maxEarlyData = maxEarlyData
                self.useBrowserForwarding = useBrowserForwarding
                self.acceptProxyProtocol = acceptProxyProtocol

        class HttpSettingsBean:
            host: list[str] = []  # str
            path: str = ""

            def __init__(self, host: list[str] = [], path: str = "") -> None:
                self.host = host
                self.path = path

        class TlsSettingsBean:
            allowInsecure: bool = False
            serverName: str = ""
            alpn: list[str] = None  # str
            minVersion: str = None
            maxVersion: str = None
            preferServerCipherSuites: bool = None
            cipherSuites: str = None
            fingerprint: str = None
            certificates: list[any] = None  # any
            disableSystemRoot: bool = None
            enableSessionResumption: bool = None
            show: bool = False
            publicKey: str = None
            shortId: str = None
            spiderX: str = None

            def __init__(
                self,
                allowInsecure: bool = False,
                serverName: str = "",
                alpn: list[str] = None,
                minVersion: str = None,
                maxVersion: str = None,
                preferServerCipherSuites: bool = None,
                cipherSuites: str = None,
                fingerprint: str = None,
                certificates: list[any] = None,
                disableSystemRoot: bool = None,
                enableSessionResumption: bool = None,
                show: bool = False,
                publicKey: str = None,
                shortId: str = None,
                spiderX: str = None,
            ) -> None:
                self.allowInsecure = allowInsecure
                self.serverName = serverName
                self.alpn = alpn
                self.minVersion = minVersion
                self.maxVersion = maxVersion
                self.preferServerCipherSuites = preferServerCipherSuites
                self.cipherSuites = cipherSuites
                self.fingerprint = fingerprint
                self.certificates = certificates
                self.disableSystemRoot = disableSystemRoot
                self.enableSessionResumption = enableSessionResumption
                self.show = show
                self.publicKey = publicKey
                self.shortId = shortId
                self.spiderX = spiderX

        class QuicSettingBean:
            class HeaderBean:
                type: str = "none"

                def __init__(self, type: str = "none") -> None:
                    self.type = type

            security: str = "none"
            key: str = ""
            header: HeaderBean = HeaderBean()

            def __init__(
                self,
                security: str = "none",
                key: str = "",
                header: HeaderBean = HeaderBean(),
            ) -> None:
                self.security = security
                self.key = key
                self.header = header

        class GrpcSettingsBean:
            serviceName: str = ""
            multiMode: bool = None

            def __init__(self, serviceName: str = "", multiMode: bool = None) -> None:
                self.serviceName = serviceName
                self.multiMode = multiMode

        network: str = DEFAULT_NETWORK
        security: str = ""
        tcpSettings: TcpSettingsBean = None
        kcpSettings: KcpSettingsBean = None
        wsSettings: WsSettingsBean = None
        httpSettings: HttpSettingsBean = None
        tlsSettings: TlsSettingsBean = None
        quicSettings: QuicSettingBean = None
        realitySettings: TlsSettingsBean = None
        grpcSettings: GrpcSettingsBean = None
        dsSettings: any = None
        sockopt: any = None

        def __init__(
            self,
            network: str = DEFAULT_NETWORK,
            security: str = "",
            tcpSettings: TcpSettingsBean = None,
            kcpSettings: KcpSettingsBean = None,
            wsSettings: WsSettingsBean = None,
            httpSettings: HttpSettingsBean = None,
            tlsSettings: TlsSettingsBean = None,
            quicSettings: QuicSettingBean = None,
            realitySettings: TlsSettingsBean = None,
            grpcSettings: GrpcSettingsBean = None,
            dsSettings: any = None,
            sockopt: any = None,
        ) -> None:
            self.network = network
            self.security = security
            self.tcpSettings = tcpSettings
            self.kcpSettings = kcpSettings
            self.wsSettings = wsSettings
            self.httpSettings = httpSettings
            self.tlsSettings = tlsSettings
            self.quicSettings = quicSettings
            self.realitySettings = realitySettings
            self.grpcSettings = grpcSettings
            self.dsSettings = dsSettings
            self.sockopt = sockopt

        def populateTransportSettings(
            self,
            transport: str,
            headerType: str,
            host: str,
            path: str,
            seed: str,
            quicSecurity: str,
            key: str,
            mode: str,
            serviceName: str,
        ) -> str:
            sni = ""
            self.network = transport
            if self.network == "tcp":
                tcpSetting = self.TcpSettingsBean()
                if headerType == HTTP:
                    tcpSetting.header.type = HTTP
                    if host != "" or path != "":
                        requestObj = self.TcpSettingsBean.HeaderBean.RequestBean()
                        requestObj.headers.Host = (
                            "" if host == None else host.split(",")
                        )
                        requestObj.path = "" if path == None else path.split(",")
                        tcpSetting.header.request = requestObj
                        sni = (
                            requestObj.headers.Host[0]
                            if len(requestObj.headers.Host) > 0
                            else sni
                        )
                else:
                    tcpSetting.header.type = "none"
                    sni = host if host != "" else ""
                self.tcpSetting = tcpSetting

            elif self.network == "kcp":
                kcpsetting = self.KcpSettingsBean()
                kcpsetting.header.type = headerType if headerType != None else "none"
                if seed == None or seed == "":
                    kcpsetting.seed = None
                else:
                    kcpsetting.seed = seed
                self.kcpSettings = kcpsetting

            elif self.network == "ws":
                wssetting = self.WsSettingsBean()
                wssetting.headers.Host = host if host != None else ""
                sni = wssetting.headers.Host
                wssetting.path = path if path != None else "/"
                self.wsSettings = wssetting

            elif self.network == "h2" or self.network == "http":
                network = "h2"
                h2Setting = self.HttpSettingsBean()
                h2Setting.host = "" if host == None else host.split(",")
                sni = h2Setting.host[0] if len(h2Setting.host) > 0 else sni
                h2Setting.path = path if path != None else "/"
                self.httpSettings = h2Setting

            elif self.network == "quic":
                quicsetting = self.QuicSettingBean()
                quicsetting.security = quicSecurity if quicSecurity != None else "none"
                quicsetting.key = key if key != None else ""
                quicsetting.header.type = headerType if headerType != None else "none"
                self.quicSettings = quicsetting

            elif self.network == "grpc":
                grpcSetting = self.GrpcSettingsBean()
                grpcSetting.multiMode = mode == "multi"
                grpcSetting.serviceName = serviceName if serviceName != None else ""
                sni = host if host != None else ""
                self.grpcSettings = grpcSetting

            return sni

        def populateTlsSettings(
            self,
            streamSecurity: str,
            allowInsecure: bool,
            sni: str,
            fingerprint: str,
            alpns: str,
            publicKey: str,
            shortId: str,
            spiderX: str
        ):
            self.security = streamSecurity
            tlsSetting = self.TlsSettingsBean(
                allowInsecure = allowInsecure,
                serverName = sni,
                fingerprint = fingerprint,
                alpn = None if alpns == None or alpns == "" else alpns.split(","),
                publicKey = publicKey,
                shortId = shortId,
                spiderX = spiderX
            )

            if self.security == TLS:
                self.tlsSettings = tlsSetting
                self.realitySettings = None
            elif self.security == REALITY:
                self.tlsSettings = None
                self.realitySettings = tlsSetting

    class MuxBean:
        enabled: bool
        concurrency: int

        def __init__(self, enabled: bool, concurrency: int = 8):
            self.enabled = enabled
            self.concurrency = concurrency

    tag: str = "proxy"
    protocol: str
    settings: OutSettingsBean = None
    streamSettings: StreamSettingsBean = None
    proxySettings: any = None
    sendThrough: str = None
    mux: MuxBean = MuxBean(False)

    def __init__(
        self,
        tag: str = "proxy",
        protocol: str = None,
        settings: OutSettingsBean = None,
        streamSettings: StreamSettingsBean = None,
        proxySettings: any = None,
        sendThrough: str = None,
        mux: MuxBean = MuxBean(enabled=False),
    ):
        self.tag = tag
        self.protocol = protocol
        self.settings = settings
        self.streamSettings = streamSettings
        self.proxySettings = proxySettings
        self.sendThrough = sendThrough
        self.mux = mux


class DnsBean:
    class ServersBean:
        address: str = ""
        port: int = None
        domains: list[str] = None  # str
        expectIPs: list[str] = None  # str
        clientIp: str = None

        def __init__(
            self,
            address: str = "",
            port: int = None,
            domains: list[str] = None,
            expectIPs: list[str] = None,
            clientIp: str = None,
        ) -> None:
            self.address = address
            self.port = port
            self.domains = domains
            self.expectIPs = expectIPs
            self.clientIp = clientIp

    servers: list[any] = None  # any
    hosts: list = None  # map(str, any)
    clientIp: str = None
    disableCache: bool = None
    queryStrategy: str = None
    tag: str = None

    def __init__(
        self,
        servers: list[any] = None,
        hosts: list = None,
        clientIp: str = None,
        disableCache: bool = None,
        queryStrategy: str = None,
        tag: str = None,
    ) -> None:
        self.servers = servers
        self.hosts = hosts
        self.clientIp = clientIp
        self.disableCache = disableCache
        self.queryStrategy = queryStrategy
        self.tag = tag


class RoutingBean:
    class RulesBean:
        type: str = ""
        ip: list[str] = None  # str
        domain: list[str] = None  # str
        outboundTag: str = ""
        balancerTag: str = None
        port: str = None
        sourcePort: str = None
        network: str = None
        source: list[str] = None  # str
        user: list[str] = None  # str
        inboundTag: list[str] = None  # str
        protocol: list[str] = None  # str
        attrs: str = None
        domainMatcher: str = None

        def __init__(
            self,
            type: str = "",
            ip: list[str] = None,
            domain: list[str] = None,
            outboundTag: str = "",
            balancerTag: str = None,
            port: str = None,
            sourcePort: str = None,
            network: str = None,
            source: list[str] = None,
            user: list[str] = None,
            inboundTag: list[str] = None,
            protocol: list[str] = None,
            attrs: str = None,
            domainMatcher: str = None,
        ) -> None:
            self.type = type
            self.ip = ip
            self.domain = domain
            self.outboundTag = outboundTag
            self.balancerTag = balancerTag
            self.port = port
            self.sourcePort = sourcePort
            self.network = network
            self.source = source
            self.user = user
            self.inboundTag = inboundTag
            self.protocol = protocol
            self.attrs = attrs
            self.domainMatcher = domainMatcher

    domainStrategy: str
    domainMatcher: str = None
    rules: list[RulesBean]  # RulesBean
    balancers: list[any]  # any

    def __init__(
        self,
        domainStrategy: str,
        domainMatcher: str = None,
        rules: list[RulesBean] = [],
        balancers: list[any] = [],
    ) -> None:
        self.domainStrategy = domainStrategy
        self.domainMatcher = domainMatcher
        self.rules = rules
        self.balancers = balancers


class FakednsBean:
    ipPool: str = "198.18.0.0/15"
    poolSize: int = 10000

    def __init__(self, ipPool: str = "198.18.0.0/15", poolSize: int = 10000) -> None:
        self.ipPool = ipPool
        self.poolSize = poolSize


class PolicyBean:
    class LevelBean:
        handshake: int = None
        connIdle: int = None
        uplinkOnly: int = None
        downlinkOnly: int = None
        statsUserUplink: bool = None
        statsUserDownlink: bool = None
        bufferSize: int = None

        def __init__(
            self,
            handshake: int = None,
            connIdle: int = None,
            uplinkOnly: int = None,
            downlinkOnly: int = None,
            statsUserUplink: bool = None,
            statsUserDownlink: bool = None,
            bufferSize: int = None,
        ) -> None:
            self.handshake = handshake
            self.connIdle = connIdle
            self.uplinkOnly = uplinkOnly
            self.downlinkOnly = downlinkOnly
            self.statsUserUplink = statsUserUplink
            self.statsUserDownlink = statsUserDownlink
            self.bufferSize = bufferSize

    levels: list  # map(str, LevelBean)
    system: any = None

    def __init__(self, levels: list, system: any = None) -> None:
        self.levels = levels
        self.system = system


class Comment:
    remark: str = None

    def __init__(self, remark: str = None) -> None:
        self.remark = remark


class V2rayConfig:
    _comment: Comment = None
    stats: any = None
    log: LogBean
    policy: PolicyBean
    inbounds: list[InboundBean]  # InboundBean
    outbounds: list[OutboundBean]  # OutboundBean
    dns: DnsBean
    routing: RoutingBean
    api: any = None
    transport: any = None
    reverse: any = None
    fakedns: any = None
    browserForwarder: any = None

    def __init__(
        self,
        _comment: Comment = None,
        stats: any = None,
        log: LogBean = None,
        policy: PolicyBean = None,
        inbounds: list = None,
        outbounds: list = None,
        dns: DnsBean = None,
        routing: RoutingBean = None,
        api: any = None,
        transport: any = None,
        reverse: any = None,
        fakedns: any = None,
        browserForwarder: any = None,
    ) -> None:
        self.stats = stats
        self._comment = _comment
        self.log = log
        self.policy = policy
        self.inbounds = inbounds
        self.outbounds = outbounds
        self.dns = dns
        self.routing = routing
        self.api = api
        self.transport = transport
        self.reverse = reverse
        self.fakedns = fakedns
        self.browserForwarder = browserForwarder


class VmessQRCode:
    v: str = ""
    ps: str = ""
    add: str = ""
    port: str = ""
    id: str = ""
    aid: str = "0"
    scy: str = ""
    net: str = ""
    type: str = ""
    host: str = ""
    path: str = ""
    tls: str = ""
    sni: str = ""
    alpn: str = ""
    allowInsecure: str = ""

    def __init__(
        self,
        v: str = "",
        ps: str = "",
        add: str = "",
        port: str = "",
        id: str = "",
        aid: str = "0",
        scy: str = "",
        net: str = "",
        type: str = "",
        host: str = "",
        path: str = "",
        tls: str = "",
        sni: str = "",
        alpn: str = "",
        allowInsecure: str = "",
        fp: str = "",
    ):
        self.v = v
        self.ps = ps
        self.add = add
        self.port = port
        self.id = id
        self.aid = aid
        self.scy = scy
        self.net = net
        self.type = type
        self.host = host
        self.path = path
        self.tls = tls
        self.sni = sni
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.fp = fp


def remove_nulls(d):
    if isinstance(d, dict):
        for k, v in list(d.items()):
            if v is None:
                del d[k]
            else:
                remove_nulls(v)
    if isinstance(d, list):
        for v in d:
            remove_nulls(v)
    return d


def get_log():
    log = LogBean(access = "", error = "", loglevel = "warning", dnsLog = False)
    return log


def get_inbound():
    inbound_socks = InboundBean(
        tag="in_proxy",
        port=10808,
        protocol="socks",
        listen="127.0.0.1",
        settings=InboundBean.InSettingsBean(
            auth="noauth",
            udp=True,
            userLevel=8,
        ),
        sniffing=InboundBean.SniffingBean(
            enabled=True,
            destOverride=["http", "tls"],
            metadataOnly=None,
        ),
        streamSettings=None,
        allocate=None,
    )
    
    inbound_http = InboundBean(
        tag="http",
        port=10809,
        protocol="http",
        listen="127.0.0.1",
        settings=InboundBean.InSettingsBean(
            userLevel=8,
        ),
        sniffing=None,
        streamSettings=None,
        allocate=None,
    )

    return inbound_socks.to_dict(), inbound_http.to_dict()


def get_outbound_vmess():
    outbound = OutboundBean(
        protocol = EConfigType.VMESS.protocolName,
        settings = OutboundBean.OutSettingsBean(
            vnext = [
                OutboundBean.OutSettingsBean.VnextBean(
                    users = [OutboundBean.OutSettingsBean.VnextBean.UsersBean()],
                ),
            ]
        ),
        streamSettings = OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_vless():
    outbound = OutboundBean(
        protocol = EConfigType.VLESS.protocolName,
        settings = OutboundBean.OutSettingsBean(
            vnext = [
                OutboundBean.OutSettingsBean.VnextBean(
                    users = [OutboundBean.OutSettingsBean.VnextBean.UsersBean()],
                ),
            ]
        ),
        streamSettings = OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_trojan():
    outbound = OutboundBean(
        protocol = EConfigType.TROJAN.protocolName,
        settings = OutboundBean.OutSettingsBean(
            servers = [OutboundBean.OutSettingsBean.ServersBean()]
        ),
        streamSettings = OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_ss():
    outbound = OutboundBean(
        protocol = "shadowsocks",
        settings = OutboundBean.OutSettingsBean(
            servers = [OutboundBean.OutSettingsBean.ServersBean()]
        ),
        streamSettings = OutboundBean.StreamSettingsBean(),
    )
    return outbound


def try_resolve_resolve_sip002(str: str, config: OutboundBean):
    try:
        uri = urlparse(str)
        config.remarks = unquote(uri.fragment or "")

        if ":" in uri.username:
            arr_user_info = list(map(str.strip, uri.username.split(":")))
            if len(arr_user_info) != 2:
                return False
            method = arr_user_info[0]
            password = unquote(arr_user_info[1])
        else:
            base64_decode = base64.b64decode(uri.username).decode(encoding = "utf-8", errors = "ignore")
            arr_user_info = list(map(str.strip, base64_decode.split(":")))
            if len(arr_user_info) < 2:
                return False
            method = arr_user_info[0]
            password = base64_decode.split(":", 1)[1]

        server = config.outbound_bean.settings.servers[0]
        server.address = uri.hostname
        server.port = uri.port
        server.password = password
        server.method = method

        return True
    except Exception as e:
        return False


def get_outbound1():
    outbound1 = OutboundBean(
        tag = "direct",
        protocol = EConfigType.FREEDOM.protocolName,
        settings = OutboundBean.OutSettingsBean(
            domainStrategy = DomainStrategy.UseIp,
        ),
        mux = None,
    )
    return outbound1


def get_outbound2():
    outbound2 = OutboundBean(
        tag = "blackhole",
        protocol = EConfigType.BLACKHOLE.protocolName,
        settings = OutboundBean.OutSettingsBean(),
        mux = None,
    )
    return outbound2


def get_dns(dns_list=["8.8.8.8"]):
    if isinstance(dns_list, str):
        if "," in dns_list:
            dns_list = dns_list.split(",")

    dns = DnsBean(servers = dns_list)
    return dns


def get_routing():
    routing = RoutingBean(domainStrategy = DomainStrategy.UseIp)
    return routing


def generateConfig(config: str, dns_list = ["8.8.8.8"]):

    allowInsecure = True

    temp = config.split("://")
    protocol = temp[0]
    raw_config = temp[1]

    if protocol == EConfigType.VMESS.protocolName:

        _len = len(raw_config)
        if _len % 4 > 0:
            raw_config += "=" * (4 - _len % 4)

        b64decode = base64.b64decode(raw_config).decode(encoding = "utf-8", errors = "ignore")
        _json = json.loads(b64decode, strict = False)

        vmessQRCode_attributes = list(VmessQRCode.__dict__["__annotations__"].keys())
        for key in list(_json.keys()):
            if key not in vmessQRCode_attributes:
                del _json[key]

        vmessQRCode = VmessQRCode(**_json)

        outbound = get_outbound_vmess()

        vnext = outbound.settings.vnext[0]
        vnext.address = vmessQRCode.add
        vnext.port = int(vmessQRCode.port)

        user = vnext.users[0]
        user.id = vmessQRCode.id
        user.security = vmessQRCode.scy if vmessQRCode.scy != "" else DEFAULT_SECURITY
        user.alterId = int(vmessQRCode.aid)

        streamSetting = outbound.streamSettings

        sni = streamSetting.populateTransportSettings(
            transport = vmessQRCode.net,
            headerType = vmessQRCode.type,
            host = vmessQRCode.host,
            path = vmessQRCode.path,
            seed = vmessQRCode.path,
            quicSecurity = vmessQRCode.host,
            key = vmessQRCode.path,
            mode = vmessQRCode.type,
            serviceName = vmessQRCode.path,
        )

        fingerprint = vmessQRCode.fp if vmessQRCode.fp else streamSetting.tlsSettings.fingerprint if streamSetting.tlsSettings else None

        streamSetting.populateTlsSettings(
            streamSecurity = vmessQRCode.tls,
            allowInsecure = allowInsecure,
            sni = sni if vmessQRCode.sni == "" else vmessQRCode.sni,
            fingerprint = fingerprint,
            alpns = vmessQRCode.alpn,
            publicKey = None,
            shortId = None,
            spiderX = None
        )

        v2rayConfig = V2rayConfig(
            _comment = Comment(remark = vmessQRCode.ps),
            log = get_log(),
            inbounds = get_inbound(),
            outbounds = [outbound, get_outbound1(), get_outbound2()],
            dns = get_dns(dns_list=dns_list),
            routing = get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.VLESS.protocolName:

        parsed_url = urlparse(config)
        _netloc = parsed_url.netloc.split("@")

        name = parsed_url.fragment
        hostname = _netloc[1].split(":")[0]
        port = int(_netloc[1].split(":")[1])
        uid = _netloc[0]

        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_url.query).items()
        )

        outbound = get_outbound_vless()

        streamSetting = outbound.streamSettings
        fingerprint = (
            streamSetting.tlsSettings.fingerprint
            if streamSetting.tlsSettings != None
            else None
        )

        vnext = outbound.settings.vnext[0]
        vnext.address = hostname
        vnext.port = port

        user = vnext.users[0]
        user.id = uid
        user.encryption = netquery.get("encryption", "none")
        user.flow = netquery.get("flow", "")

        sni = streamSetting.populateTransportSettings(
            transport = netquery.get("type", "tcp"),
            headerType = netquery.get("headerType", None),
            host = netquery.get("host", None),
            path = netquery.get("path", None),
            seed = netquery.get("seed", None),
            quicSecurity = netquery.get("quicSecurity", None),
            key = netquery.get("key", None),
            mode = netquery.get("mode", None),
            serviceName = netquery.get("serviceName", None),
        )
        streamSetting.populateTlsSettings(
            streamSecurity = netquery.get("security", ""),
            allowInsecure = allowInsecure,
            sni = sni if netquery.get("sni", None) == None else netquery.get("sni", None),
            fingerprint = fingerprint,
            alpns = netquery.get("alpn", None),
            publicKey = netquery.get("pbk", ""),
            shortId = netquery.get("sid", ""),
            spiderX = netquery.get("spx", ""),
        )

        v2rayConfig = V2rayConfig(
            _comment = Comment(remark = name),
            log = get_log(),
            inbounds = get_inbound(),
            outbounds = [outbound, get_outbound1(), get_outbound2()],
            dns = get_dns(dns_list = dns_list),
            routing = get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default = vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.TROJAN.protocolName:

        parsed_url = urlparse(config)
        _netloc = parsed_url.netloc.split("@")

        name = parsed_url.fragment
        hostname = _netloc[1].split(":")[0]
        port = int(_netloc[1].split(":")[1])
        uid = _netloc[0]

        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_url.query).items()
        )

        outbound = get_outbound_trojan()

        streamSetting = outbound.streamSettings

        flow = ""
        fingerprint = (
            streamSetting.tlsSettings.fingerprint
            if streamSetting.tlsSettings != None
            else Fingerprint.randomized
        )

        if len(netquery) > 0:
            sni = streamSetting.populateTransportSettings(
                transport = netquery.get("type", "tcp"),
                headerType = netquery.get("headerType", None),
                host = netquery.get("host", None),
                path = netquery.get("path", None),
                seed = netquery.get("seed", None),
                quicSecurity = netquery.get("quicSecurity", None),
                key = netquery.get("key", None),
                mode = netquery.get("mode", None),
                serviceName = netquery.get("serviceName", None),
            )

            streamSetting.populateTlsSettings(
                streamSecurity = netquery.get("security", TLS),
                allowInsecure = allowInsecure,
                sni = sni if netquery.get("sni", None) == None else netquery.get("sni", None),
                fingerprint = fingerprint,
                alpns = netquery.get("alpn", None),
                publicKey = None,
                shortId = None,
                spiderX = None,
            )

            flow = netquery.get("flow", "")

        else:
            streamSetting.populateTlsSettings(
                streamSecurity = TLS,
                allowInsecure = allowInsecure,
                sni = "",
                fingerprint = fingerprint,
                alpns = None,
                publicKey = None,
                shortId = None,
                spiderX = None,
            )

        server = outbound.settings.servers[0]
        server.address = hostname
        server.port = port
        server.password = uid
        server.flow = flow

        v2rayConfig = V2rayConfig(
            _comment = Comment(remark = name),
            log = get_log(),
            inbounds = get_inbound(),
            outbounds = [outbound, get_outbound1(), get_outbound2()],
            dns = get_dns(dns_list = dns_list),
            routing = get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default = vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)
    
    elif protocol == EConfigType.SHADOWSOCKS.protocolName:
        outbound = get_outbound_ss()
        if not try_resolve_resolve_sip002(raw_config, outbound):
            result = raw_config.replace(EConfigType.SHADOWSOCKS.protocolScheme, "")
            index_split = result.find("#")
            if index_split > 0:
                try:
                    outbound.remarks = unquote(result[index_split + 1:])
                except Exception as e:
                    None # print(e)

                result = result[:index_split]

            # part decode
            index_s = result.find("@")
            result = base64.b64decode(result[:index_s]).decode(encoding = "utf-8", errors = "ignore") + result[index_s:] if index_s > 0 else base64.b64decode(result).decode(encoding = "utf-8", errors = "ignore")

            legacy_pattern = re.compile(r'^(.+?):(.*)@(.+):(\d+)\/?.*$')
            match = legacy_pattern.match(result)

            if not match:
                raise Exception("Incorrect protocol")

            server = outbound.settings.servers[0]
            server.address = match.group(3).strip("[]")
            server.port = int(match.group(4))
            server.password = match.group(2)
            server.method = match.group(1).lower()

            v2rayConfig = V2rayConfig(
                _comment = Comment(remark = outbound.remarks),
                log = get_log(),
                inbounds = get_inbound(),
                outbounds = [outbound, get_outbound1(), get_outbound2()],
                dns = get_dns(dns_list = dns_list),
                routing = get_routing(),
            )

            v2rayConfig_str_json = json.dumps(v2rayConfig, default = vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)


# GUI
app = tk.Tk()
app.title("V2rayAGN")


icon_path = os.path.join(base_path, 'resources', 'img', 'app_icon.ico')
app.iconbitmap(icon_path)

center_window(app)
app.resizable(False, False)

# init db
ensure_db()
init_db()


# load and resize icons
start_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'start_icon.png'))
stop_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'stop_icon.png'))
import_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'import_icon.png'))
edit_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'edit_icon.png'))
export_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'export_icon.png'))
delete_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'delete_icon.png'))
app_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'app_icon.png'))

custom_font = font.Font(family="Helvetica", size=12, weight="bold")


title_label = Label(app, text="V2rayAGN Windows", fg="black", font=custom_font, image=app_icon, compound=tk.LEFT)
title_label.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="n")

# start/import buttons
buttons_frame = tk.Frame(app)
buttons_frame.grid(row=2, column=2, padx=10, pady=5, sticky="n")
import_btn = Button(buttons_frame, text="Import Config", command=on_import, image=import_icon, compound=tk.LEFT)
import_btn.pack(pady=(0, 15))  
start_stop_button = Button(buttons_frame, text="Start V2Ray", command=toggle_v2ray, image=start_icon, compound=tk.LEFT) 
start_stop_button.pack(pady=(0, 5))  

# profiles Combobox
Label(app, text="Profiles:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
profiles_combobox = ttk.Combobox(app, state="readonly")
profiles_combobox.grid(row=2, column=1, padx=10, pady=5, sticky="we")
profiles_combobox.bind("<<ComboboxSelected>>", load_profile)

# connection statistics 
stats_frame = tk.Frame(app)
stats_frame.grid(row=3, column=0, columnspan=3, padx=10, pady=5, sticky='ew')
stats_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)
Label(stats_frame, text="Data Usage:", anchor='e').grid(row=0, column=0, padx=(10, 5), pady=5, sticky='e')
data_usage_label = Label(stats_frame, text="0.00 MB", anchor='w')
data_usage_label.grid(row=0, column=1, padx=(0, 20), pady=5, sticky='w')
Label(stats_frame, text="Connection Duration:", anchor='e').grid(row=0, column=2, padx=(10, 5), pady=5, sticky='e')
duration_label = Label(stats_frame, text="0 s", anchor='w')
duration_label.grid(row=0, column=3, padx=(0, 20), pady=5, sticky='w')
Label(stats_frame, text="Current Speed:", anchor='e').grid(row=0, column=4, padx=(10, 5), pady=5, sticky='e')
speed_label = Label(stats_frame, text="0.00 KB/s", anchor='w')
speed_label.grid(row=0, column=5, padx=(0, 10), pady=5, sticky='w')

# edit, delete, export Profile
profile_buttons_frame = tk.Frame(app)
profile_buttons_frame.grid(row=4, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
profile_buttons_frame.grid_columnconfigure(0, weight=1)
profile_buttons_frame.grid_columnconfigure(1, weight=1)
profile_buttons_frame.grid_columnconfigure(2, weight=1)
Button(profile_buttons_frame, text="Edit Profile", command=edit_profile, image=edit_icon, compound=tk.LEFT).grid(row=0, column=0, padx=10, pady=5, sticky="e")
Button(profile_buttons_frame, text="Delete Profile", command=delete_profile, image=delete_icon, compound=tk.LEFT).grid(row=0, column=1, padx=10, pady=5)
Button(profile_buttons_frame, text="Export Profile", command=export_profile, image=export_icon, compound=tk.LEFT).grid(row=0, column=2, padx=10, pady=5, sticky="w")

# logs Section
pane = tk.PanedWindow(app, orient=tk.VERTICAL)
pane.grid(row=5, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")
log_text = ScrolledText(pane, height=10, width=60, state=tk.DISABLED)
pane.add(log_text)

# copyright
footer = tk.Text(app, height=1, bd=0, relief=tk.SUNKEN, font=("Helvetica", 10), wrap="none")
footer.grid(row=6, column=0, columnspan=3, sticky='we', padx=10, pady=(10, 0))

footer.insert(tk.END, "HTTP/Socks Proxy: ")
footer.insert(tk.END, "Not Set", "not_set")
footer.insert(tk.END, " | © 2024 by Khaled AGN")
footer.tag_configure("not_set", foreground="red")
footer.tag_configure("center", justify='center')
footer.tag_add("center", "1.0", "end")
footer.config(state=tk.DISABLED)

# follow on social media
social_frame = tk.Frame(app)
social_frame.grid(row=7, column=0, columnspan=3, pady=(10, 0))
telegram_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'telegram.png'), size=(18, 18))
youtube_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'youtube.png'), size=(18, 18))
facebook_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'facebook.png'), size=(18, 18))
instagram_icon = resize_icon(os.path.join(base_path, 'resources', 'img', 'instagram.png'), size=(18, 18))
Button(social_frame, image=telegram_icon, command=lambda: open_link("https://t.me/khaledagn")).pack(side=tk.LEFT, pady=5, padx=5)
Button(social_frame, image=youtube_icon, command=lambda: open_link("https://www.youtube.com/c/KhaledAGN")).pack(side=tk.LEFT, pady=5, padx=5)
Button(social_frame, image=facebook_icon, command=lambda: open_link("https://www.facebook.com/itskhaledagn")).pack(side=tk.LEFT, pady=5, padx=5)
Button(social_frame, image=instagram_icon, command=lambda: open_link("https://www.instagram.com/khaledagn")).pack(side=tk.LEFT, pady=5, padx=5)

app.grid_rowconfigure(5, weight=1)
app.grid_columnconfigure(1, weight=1)

# hide the stats frame initially
stats_frame.grid_remove()

# load profiles into the combobox
load_profiles()

# load initial profile 
load_initial_profile()

app.mainloop()
