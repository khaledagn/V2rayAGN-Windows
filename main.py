import os
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
def run_v2ray2json(url):
    try:
        result = subprocess.run(['python', 'v2ray2json.py', url], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        log(f"Error: {e}")
        return None


# import config from clipboard
def import_config_from_clipboard():
    url = pyperclip.paste()
    if any(url.startswith(prefix) for prefix in ["vmess://", "vless://", "trojan://", "ss://"]):
        config_json = run_v2ray2json(url)
    else:
        try:
          
            config_json = json.loads(url)
            config_json = json.dumps(config_json, indent=4)   
        except json.JSONDecodeError:
            log("Invalid configuration format.")
            messagebox.showerror("Error", "Invalid configuration format.")
            return None
    return config_json


# import config from file
def import_config_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("V2Ray Config", "*.v2agn")])
    if file_path:
        try:
            with open(file_path, 'r') as file:
                data = file.read().strip()
                if any(data.startswith(prefix) for prefix in ["vmess://", "vless://", "trojan://", "ss://"]):
                    config_json = run_v2ray2json(data)
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


# on import click
def on_import():
    dialog = tk.Toplevel(app)
    dialog.title("Import Config")
    app_icon = ImageTk.PhotoImage(file=os.path.join(base_path, 'resources', 'img', 'app_icon.png'))
    dialog.iconphoto(False, app_icon)
    dialog.geometry("400x300")
    

    # center import dialog
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
        dialog.destroy()
        if config_json:
            generate_v2ray_config(config_json, profile_name)
    
    def from_file():
        dialog.destroy()
        config_json, profile_name = import_config_from_file()
        if config_json:
            generate_v2ray_config(config_json, profile_name)
    
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


# start v2ray
def start_v2ray():
    global v2ray_process, start_time, data_sent, data_received
    selected_profile = profiles_combobox.get()
    if selected_profile:
        profile_config = get_profile_config_from_db(selected_profile)
        if profile_config:
            with open(CONFIG_PATH, 'w') as file:
                file.write(profile_config)
            v2ray_process = subprocess.Popen([V2RAY_BINARY, "-config", CONFIG_PATH])
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
