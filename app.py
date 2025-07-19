#!/usr/bin/env python3
"""
TransferD Web - Local Network File Transfer Application
Web-based version with Flask and SocketIO for Docker deployment.
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import os
import json
import hashlib
import socket
import threading
import time
from pathlib import Path
from cryptography.fernet import Fernet
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
import asyncio
import websockets
import urllib.request
import urllib.parse

app = Flask(__name__)
app.config['SECRET_KEY'] = 'transferd-secret-key'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

socketio = SocketIO(app, cors_allowed_origins="*")

class TransferDWeb:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.port = 8080
        self.websocket_port = 8081
        self.devices = []
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.password = None
        self.zeroconf = None
        self.service_info = None
        
        # Ensure downloads directory exists
        self.downloads_dir = Path('/app/downloads')
        self.downloads_dir.mkdir(exist_ok=True)
        
        # Start services
        self.start_discovery()
        self.start_websocket_server()
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def add_discovered_device(self, ip, port):
        device_info = f"{ip}:{port}"
        if device_info not in self.devices and ip != self.local_ip:
            self.devices.append(device_info)
            socketio.emit('device_discovered', {'device': device_info}, broadcast=True)
            self.log_status(f"Discovered device: {device_info}")
    
    def log_status(self, message):
        timestamp = time.strftime('%H:%M:%S')
        socketio.emit('status_update', {
            'timestamp': timestamp,
            'message': message
        }, broadcast=True)
    
    def start_discovery(self):
        def discovery_thread():
            try:
                self.zeroconf = Zeroconf()
                
                # Register our service
                service_name = f"TransferD-{self.local_ip.replace('.', '-')}._transferd._tcp.local."
                self.service_info = ServiceInfo(
                    "_transferd._tcp.local.",
                    service_name,
                    addresses=[socket.inet_aton(self.local_ip)],
                    port=self.port,
                    properties={b"version": b"2.0"}
                )
                self.zeroconf.register_service(self.service_info)
                
                # Start browsing for other services
                listener = DeviceListener(self)
                browser = ServiceBrowser(self.zeroconf, "_transferd._tcp.local.", listener)
                self.log_status("Device discovery started")
                
                # Keep discovery running
                while True:
                    time.sleep(10)
                    
            except Exception as e:
                self.log_status(f"Discovery error: {str(e)}")
        
        threading.Thread(target=discovery_thread, daemon=True).start()
    
    def start_websocket_server(self):
        async def handle_message(websocket, path):
            try:
                async for message in websocket:
                    try:
                        decrypted = self.cipher.decrypt(message.encode()).decode()
                        socketio.emit('message_received', {
                            'message': decrypted,
                            'timestamp': time.strftime('%H:%M:%S')
                        }, broadcast=True)
                        self.log_status(f"Received message: {decrypted[:50]}...")
                    except:
                        self.log_status("Received encrypted message")
            except websockets.exceptions.ConnectionClosed:
                pass
        
        def run_websocket_server():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                start_server = websockets.serve(handle_message, "0.0.0.0", self.websocket_port)
                loop.run_until_complete(start_server)
                loop.run_forever()
            except Exception as e:
                self.log_status(f"WebSocket server error: {str(e)}")
        
        threading.Thread(target=run_websocket_server, daemon=True).start()
        self.log_status(f"WebSocket server started on {self.local_ip}:{self.websocket_port}")

class DeviceListener:
    def __init__(self, app):
        self.app = app
        
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            self.app.add_discovered_device(ip, info.port)
    
    def remove_service(self, zc, type_, name):
        pass

# Initialize the app
transfer_app = TransferDWeb()

@app.route('/')
def index():
    return render_template('index.html', 
                         local_ip=transfer_app.local_ip, 
                         port=transfer_app.port)

@app.route('/api/devices')
def get_devices():
    return jsonify({
        'devices': transfer_app.devices,
        'local_ip': transfer_app.local_ip,
        'port': transfer_app.port
    })

@app.route('/api/devices', methods=['POST'])
def add_device():
    data = request.get_json()
    ip_port = data.get('device', '').strip()
    
    if ip_port:
        if ':' not in ip_port:
            ip_port += ':8080'
        if ip_port not in transfer_app.devices:
            transfer_app.devices.append(ip_port)
            transfer_app.log_status(f"Added device: {ip_port}")
            return jsonify({'success': True, 'device': ip_port})
    
    return jsonify({'success': False, 'error': 'Invalid device format'})

@app.route('/api/password', methods=['POST'])
def set_password():
    data = request.get_json()
    password = data.get('password', '').strip()
    
    if password:
        transfer_app.password = password
        transfer_app.log_status("Password protection enabled")
    else:
        transfer_app.password = None
        transfer_app.log_status("Password protection disabled")
    
    return jsonify({'success': True})

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save file to downloads directory
        filename = file.filename
        file_path = transfer_app.downloads_dir / filename
        file.save(str(file_path))
        
        file_size = file_path.stat().st_size
        transfer_app.log_status(f"File received: {filename} ({file_size/1024/1024:.1f}MB)")
        
        return jsonify({'success': True, 'filename': filename})
    
    except Exception as e:
        transfer_app.log_status(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/send_file', methods=['POST'])
def send_file():
    try:
        data = request.get_json()
        target_device = data.get('device')
        file_data = data.get('file_data')
        filename = data.get('filename')
        
        if not all([target_device, file_data, filename]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Decode base64 file data
        import base64
        file_content = base64.b64decode(file_data)
        
        # Prepare multipart form data
        boundary = '----WebKitFormBoundary' + hashlib.md5(str(time.time()).encode()).hexdigest()
        body = f'--{boundary}\r\n'
        body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        body += 'Content-Type: application/octet-stream\r\n\r\n'
        body = body.encode() + file_content + f'\r\n--{boundary}--\r\n'.encode()
        
        # Send to target device
        url = f"http://{target_device}/upload"
        req = urllib.request.Request(url, data=body)
        req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
        
        with urllib.request.urlopen(req) as response:
            transfer_app.log_status(f"File sent successfully: {filename} to {target_device}")
            return jsonify({'success': True})
    
    except Exception as e:
        transfer_app.log_status(f"Error sending file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/send_message', methods=['POST'])
def send_message():
    try:
        data = request.get_json()
        target_device = data.get('device')
        message = data.get('message')
        
        if not all([target_device, message]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        def send_async():
            try:
                encrypted_text = transfer_app.cipher.encrypt(message.encode()).decode()
                ip, port = target_device.split(':')
                websocket_port = int(port) + 1
                
                async def send_ws_message():
                    uri = f"ws://{ip}:{websocket_port}"
                    async with websockets.connect(uri) as websocket:
                        await websocket.send(encrypted_text)
                
                asyncio.run(send_ws_message())
                transfer_app.log_status(f"Sent message to {target_device}: {message[:50]}...")
            except Exception as e:
                transfer_app.log_status(f"Error sending message: {str(e)}")
        
        threading.Thread(target=send_async, daemon=True).start()
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/downloads/<path:filename>')
def download_file(filename):
    return send_from_directory(transfer_app.downloads_dir, filename)

@socketio.on('connect')
def handle_connect():
    emit('status_update', {
        'timestamp': time.strftime('%H:%M:%S'),
        'message': 'Connected to TransferD'
    })

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=False)