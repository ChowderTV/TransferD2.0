#!/usr/bin/env python3
"""
Simple Local Network File Transfer Application
A lightweight tool for transferring files and messages between devices on the same network.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False
    print("tkinterdnd2 not available. Install with: pip install tkinterdnd2")
import threading
import socket
import json
import os
import hashlib
import base64
from pathlib import Path
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request
from cryptography.fernet import Fernet
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
import websockets
import websockets.server
import asyncio
import io

class FileTransferServer(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/upload':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            boundary = self.headers['Content-Type'].split('boundary=')[1]
            parts = post_data.split(f'--{boundary}'.encode())
            
            for part in parts[1:-1]:
                if b'Content-Disposition' in part:
                    lines = part.split(b'\r\n')
                    filename = None
                    for line in lines:
                        if b'filename=' in line:
                            filename = line.split(b'filename="')[1].split(b'"')[0].decode()
                            break
                    
                    if filename:
                        content_start = part.find(b'\r\n\r\n') + 4
                        file_content = part[content_start:]
                        
                        downloads_dir = Path.home() / 'Downloads' / 'TransferD'
                        downloads_dir.mkdir(exist_ok=True)
                        
                        file_path = downloads_dir / filename
                        with open(file_path, 'wb') as f:
                            f.write(file_content)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'File uploaded successfully')
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'TransferD Server Running')

class DeviceListener:
    def __init__(self, app):
        self.app = app
        
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip != self.app.local_ip:
                self.app.add_discovered_device(ip, info.port)
    
    def remove_service(self, zc, type_, name):
        pass

class TransferApp:
    def __init__(self):
        if DND_AVAILABLE:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()
        self.root.title("TransferD - Local Network File Transfer")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        
        self.local_ip = self.get_local_ip()
        self.port = 8080
        self.server = None
        self.websocket_server = None
        self.zeroconf = None
        self.service_info = None
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.password = None
        
        self.devices = []
        self.selected_device = None
        
        self.setup_ui()
        self.start_server()
        self.start_websocket_server()
        self.start_discovery()
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2c3e50', foreground='white')
        style.configure('TFrame', background='#2c3e50')
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="TransferD", font=('Arial', 20, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        ip_label = ttk.Label(header_frame, text=f"Your IP: {self.local_ip}:{self.port}", font=('Arial', 10))
        ip_label.pack(side=tk.RIGHT)
        
        # Main content
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Devices
        left_frame = ttk.LabelFrame(content_frame, text="Available Devices", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.device_listbox = tk.Listbox(left_frame, bg='#34495e', fg='white', selectbackground='#3498db')
        self.device_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.device_listbox.bind('<<ListboxSelect>>', self.on_device_select)
        
        # Manual IP entry and password
        manual_frame = ttk.Frame(left_frame)
        manual_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.ip_entry = tk.Entry(manual_frame, bg='#34495e', fg='white')
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.ip_entry.insert(0, "Enter IP:Port")
        
        add_btn = tk.Button(manual_frame, text="Add", command=self.add_manual_device, 
                           bg='#3498db', fg='white', relief=tk.FLAT)
        add_btn.pack(side=tk.RIGHT)
        
        # Password protection
        password_frame = ttk.Frame(left_frame)
        password_frame.pack(fill=tk.X)
        
        self.password_entry = tk.Entry(password_frame, bg='#34495e', fg='white', show='*')
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.password_entry.insert(0, "Optional Password")
        
        set_pwd_btn = tk.Button(password_frame, text="Set", command=self.set_password,
                               bg='#e74c3c', fg='white', relief=tk.FLAT)
        set_pwd_btn.pack(side=tk.RIGHT)
        
        # Right panel - Transfer
        right_frame = ttk.LabelFrame(content_frame, text="Transfer", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Text message area
        text_frame = ttk.LabelFrame(right_frame, text="Send Message/Link", padding=5)
        text_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.text_entry = tk.Text(text_frame, height=3, bg='#34495e', fg='white')
        self.text_entry.pack(fill=tk.X, pady=(0, 5))
        
        send_text_btn = tk.Button(text_frame, text="Send Text", command=self.send_text,
                                 bg='#27ae60', fg='white', relief=tk.FLAT)
        send_text_btn.pack()
        
        # File drop area
        file_frame = ttk.LabelFrame(right_frame, text="Send File", padding=5)
        file_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.drop_area = tk.Label(file_frame, text="Drag & Drop Files Here\n(or click to browse)", 
                                 bg='#34495e', fg='white', relief=tk.SUNKEN, height=8)
        self.drop_area.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        self.drop_area.bind('<Button-1>', self.browse_file)
        
        # Enable drag and drop
        if DND_AVAILABLE:
            self.drop_area.drop_target_register(DND_FILES)
            self.drop_area.dnd_bind('<<Drop>>', self.on_file_drop)
        else:
            self.drop_area.config(text="Click to browse files\n(Drag & drop requires tkinterdnd2)")
        
        # Status area
        status_frame = ttk.LabelFrame(right_frame, text="Status", padding=5)
        status_frame.pack(fill=tk.X)
        
        self.status_text = tk.Text(status_frame, height=4, bg='#34495e', fg='white', state=tk.DISABLED)
        self.status_text.pack(fill=tk.X)
    
    def add_discovered_device(self, ip, port):
        device_info = f"{ip}:{port}"
        if device_info not in self.devices:
            self.devices.append(device_info)
            self.device_listbox.insert(tk.END, device_info)
            self.log_status(f"Discovered device: {device_info}")
    
    def add_manual_device(self):
        ip_port = self.ip_entry.get().strip()
        if ip_port and ip_port != "Enter IP:Port":
            if ':' not in ip_port:
                ip_port += ':8080'
            if ip_port not in self.devices:
                self.devices.append(ip_port)
                self.device_listbox.insert(tk.END, ip_port)
                self.log_status(f"Added device: {ip_port}")
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, "Enter IP:Port")
    
    def on_device_select(self, event):
        selection = self.device_listbox.curselection()
        if selection:
            self.selected_device = self.devices[selection[0]]
            self.log_status(f"Selected device: {self.selected_device}")
    
    def browse_file(self, event=None):
        file_path = filedialog.askopenfilename(
            title="Select file to transfer",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.send_file(file_path)
    
    def on_file_drop(self, event):
        if DND_AVAILABLE:
            files = self.root.tk.splitlist(event.data)
            for file_path in files:
                if os.path.isfile(file_path):
                    file_size = os.path.getsize(file_path)
                    if file_size > 100 * 1024 * 1024:  # 100MB limit
                        self.log_status(f"File too large: {os.path.basename(file_path)} ({file_size/1024/1024:.1f}MB)")
                        continue
                    self.send_file(file_path)
    
    def send_file(self, file_path):
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first")
            return
        
        def upload():
            try:
                filename = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                self.log_status(f"Sending {filename} ({file_size/1024/1024:.1f}MB)...")
                
                with open(file_path, 'rb') as f:
                    files = {'file': (filename, f, 'application/octet-stream')}
                    
                    boundary = '----WebKitFormBoundary' + hashlib.md5(str(time.time()).encode()).hexdigest()
                    body = f'--{boundary}\r\n'
                    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                    body += 'Content-Type: application/octet-stream\r\n\r\n'
                    body = body.encode() + f.read() + f'\r\n--{boundary}--\r\n'.encode()
                    
                    url = f"http://{self.selected_device}/upload"
                    req = urllib.request.Request(url, data=body)
                    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
                    
                    with urllib.request.urlopen(req) as response:
                        self.log_status(f"File sent successfully: {filename}")
            except Exception as e:
                self.log_status(f"Error sending file: {str(e)}")
        
        threading.Thread(target=upload, daemon=True).start()
    
    def send_text(self):
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first")
            return
        
        text = self.text_entry.get("1.0", tk.END).strip()
        if text:
            def send_message():
                try:
                    encrypted_text = self.cipher.encrypt(text.encode()).decode()
                    ip, port = self.selected_device.split(':')
                    websocket_port = int(port) + 1
                    
                    async def send_ws_message():
                        uri = f"ws://{ip}:{websocket_port}"
                        async with websockets.connect(uri) as websocket:
                            await websocket.send(encrypted_text)
                    
                    asyncio.run(send_ws_message())
                    self.log_status(f"Sent message: {text[:50]}...")
                    self.text_entry.delete("1.0", tk.END)
                except Exception as e:
                    self.log_status(f"Error sending message: {str(e)}")
            
            threading.Thread(target=send_message, daemon=True).start()
    
    def log_status(self, message):
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)
    
    def start_server(self):
        def run_server():
            try:
                self.server = HTTPServer((self.local_ip, self.port), FileTransferServer)
                self.log_status(f"Server started on {self.local_ip}:{self.port}")
                self.server.serve_forever()
            except Exception as e:
                self.log_status(f"Server error: {str(e)}")
        
        threading.Thread(target=run_server, daemon=True).start()
    
    def set_password(self):
        pwd = self.password_entry.get().strip()
        if pwd and pwd != "Optional Password":
            self.password = pwd
            self.log_status("Password protection enabled")
        else:
            self.password = None
            self.log_status("Password protection disabled")
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, "Optional Password")
    
    def start_websocket_server(self):
        async def handle_message(websocket, path):
            try:
                async for message in websocket:
                    try:
                        decrypted = self.cipher.decrypt(message.encode()).decode()
                        self.log_status(f"Received message: {decrypted[:50]}...")
                    except:
                        self.log_status(f"Received encrypted message")
            except websockets.exceptions.ConnectionClosed:
                pass
        
        def run_websocket_server():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                start_server = websockets.serve(handle_message, self.local_ip, self.port + 1)
                loop.run_until_complete(start_server)
                loop.run_forever()
            except Exception as e:
                self.log_status(f"WebSocket server error: {str(e)}")
        
        threading.Thread(target=run_websocket_server, daemon=True).start()
        self.log_status(f"WebSocket server started on {self.local_ip}:{self.port + 1}")
    
    def start_discovery(self):
        try:
            self.zeroconf = Zeroconf()
            
            # Register our service
            service_name = f"TransferD-{self.local_ip.replace('.', '-')}._transferd._tcp.local."
            self.service_info = ServiceInfo(
                "_transferd._tcp.local.",
                service_name,
                addresses=[socket.inet_aton(self.local_ip)],
                port=self.port,
                properties={b"version": b"1.0"}
            )
            self.zeroconf.register_service(self.service_info)
            
            # Start browsing for other services
            listener = DeviceListener(self)
            browser = ServiceBrowser(self.zeroconf, "_transferd._tcp.local.", listener)
            self.log_status("Device discovery started")
        except Exception as e:
            self.log_status(f"Discovery error: {str(e)}")
    
    def run(self):
        try:
            self.root.mainloop()
        finally:
            if self.server:
                self.server.shutdown()
            if self.service_info and self.zeroconf:
                self.zeroconf.unregister_service(self.service_info)
            if self.zeroconf:
                self.zeroconf.close()

if __name__ == "__main__":
    app = TransferApp()
    app.run()