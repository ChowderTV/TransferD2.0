#!/usr/bin/env python3
"""
TransferD Web - Local Network File Transfer Application
Secure web-based version with Flask and SocketIO for Docker deployment.
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import os
import json
import hashlib
import socket
import threading
import time
import re
import secrets
from pathlib import Path
from collections import defaultdict, deque
from cryptography.fernet import Fernet
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
import urllib.request
import urllib.parse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate secure random key
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

# Restrict CORS to localhost and private networks only
socketio = SocketIO(app, cors_allowed_origins=[
    "http://localhost:*",
    "http://127.0.0.1:*", 
    "http://192.168.*:*",
    "http://10.*:*",
    "http://172.16.*:*",
    "http://172.17.*:*",
    "http://172.18.*:*",
    "http://172.19.*:*",
    "http://172.20.*:*",
    "http://172.21.*:*",
    "http://172.22.*:*",
    "http://172.23.*:*",
    "http://172.24.*:*",
    "http://172.25.*:*",
    "http://172.26.*:*",
    "http://172.27.*:*",
    "http://172.28.*:*",
    "http://172.29.*:*",
    "http://172.30.*:*",
    "http://172.31.*:*"
])

# Rate limiting configuration
RATE_LIMIT_WINDOW = 60  # 1 minute window
MAX_REQUESTS_PER_MINUTE = 10
MAX_UPLOAD_SIZE_PER_MINUTE = 50 * 1024 * 1024  # 50MB per minute

class RateLimiter:
    def __init__(self):
        self.request_counts = defaultdict(deque)
        self.upload_sizes = defaultdict(deque)
    
    def is_allowed(self, client_ip, upload_size=0):
        current_time = time.time()
        
        # Clean old entries
        cutoff_time = current_time - RATE_LIMIT_WINDOW
        
        # Clean request counts
        while self.request_counts[client_ip] and self.request_counts[client_ip][0] < cutoff_time:
            self.request_counts[client_ip].popleft()
        
        # Clean upload sizes
        while self.upload_sizes[client_ip] and self.upload_sizes[client_ip][0][0] < cutoff_time:
            self.upload_sizes[client_ip].popleft()
        
        # Check request rate limit
        if len(self.request_counts[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
            return False
        
        # Check upload size limit
        total_upload_size = sum(size for _, size in self.upload_sizes[client_ip])
        if total_upload_size + upload_size > MAX_UPLOAD_SIZE_PER_MINUTE:
            return False
        
        # Add current request
        self.request_counts[client_ip].append(current_time)
        if upload_size > 0:
            self.upload_sizes[client_ip].append((current_time, upload_size))
        
        return True

rate_limiter = RateLimiter()

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal attacks"""
    if not filename:
        return "unnamed_file"
    
    # Remove path components and keep only the filename
    filename = os.path.basename(filename)
    
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Ensure filename is not empty after sanitization
    if not filename or filename == '.' or filename == '..':
        filename = f"file_{secrets.token_hex(8)}"
    
    # Limit filename length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext[:5]
    
    return filename

def validate_ip_port(ip_port_str):
    """Validate IP:port format and return sanitized version"""
    if not ip_port_str or ip_port_str.strip() == "Enter IP:Port":
        return None
    
    ip_port_str = ip_port_str.strip()
    
    # Add default port if missing
    if ':' not in ip_port_str:
        ip_port_str += ':8080'
    
    try:
        ip, port = ip_port_str.split(':', 1)
        
        # Validate IP address format
        parts = ip.split('.')
        if len(parts) != 4:
            return None
        
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return None
        
        # Validate port
        port_num = int(port)
        if not 1 <= port_num <= 65535:
            return None
        
        return f"{ip}:{port_num}"
    except ValueError:
        return None

def sanitize_text_message(text):
    """Sanitize text message to prevent injection attacks"""
    if not text:
        return ""
    
    # Limit message length
    text = text[:10000]
    
    # Remove control characters except newlines and tabs
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    return text

def check_authentication(password_required):
    """Check if request is authenticated when password is required"""
    if not password_required:
        return True
    
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return False
    
    return auth_header[7:] == password_required

def get_client_ip():
    """Get client IP address from request"""
    # Check for forwarded headers first (for reverse proxies)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or '127.0.0.1'

class TransferDWeb:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.port = 8080
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
            socketio.emit('device_discovered', {'device': device_info})
            self.log_status(f"Discovered device: {device_info}")
    
    def log_status(self, message):
        timestamp = time.strftime('%H:%M:%S')
        socketio.emit('status_update', {
            'timestamp': timestamp,
            'message': message
        })
    
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
    try:
        # Rate limiting
        client_ip = get_client_ip()
        if not rate_limiter.is_allowed(client_ip):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Authentication check
        if not check_authentication(transfer_app.password):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
            
        ip_port_input = data.get('device', '').strip()
        validated_ip_port = validate_ip_port(ip_port_input)
        
        if validated_ip_port:
            if validated_ip_port not in transfer_app.devices:
                transfer_app.devices.append(validated_ip_port)
                transfer_app.log_status(f"Added device: {validated_ip_port}")
                return jsonify({'success': True, 'device': validated_ip_port})
            else:
                return jsonify({'error': 'Device already exists'}), 400
        else:
            return jsonify({'error': 'Invalid IP address format'}), 400
    
    except Exception:
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/password', methods=['POST'])
def set_password():
    try:
        # Rate limiting
        client_ip = get_client_ip()
        if not rate_limiter.is_allowed(client_ip):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
            
        password = data.get('password', '')
        if not isinstance(password, str):
            return jsonify({'error': 'Invalid password format'}), 400
            
        password = password.strip()
        
        # Limit password length
        if len(password) > 1000:
            return jsonify({'error': 'Password too long'}), 400
        
        if password:
            transfer_app.password = password
            transfer_app.log_status("Password protection enabled")
        else:
            transfer_app.password = None
            transfer_app.log_status("Password protection disabled")
        
        return jsonify({'success': True})
    
    except Exception:
        return jsonify({'error': 'Server error'}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        # Rate limiting and size check
        client_ip = get_client_ip()
        content_length = request.content_length or 0
        
        if not rate_limiter.is_allowed(client_ip, content_length):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Authentication check
        if not check_authentication(transfer_app.password):
            return jsonify({'error': 'Authentication required'}), 401
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(file.filename)
        file_path = transfer_app.downloads_dir / safe_filename
        
        # Ensure we're still within the downloads directory
        if not str(file_path.resolve()).startswith(str(transfer_app.downloads_dir.resolve())):
            return jsonify({'error': 'Invalid file path'}), 400
        
        # Save file to downloads directory
        file.save(str(file_path))
        
        file_size = file_path.stat().st_size
        transfer_app.log_status(f"File received: {safe_filename} ({file_size/1024/1024:.1f}MB)")
        
        return jsonify({'success': True, 'filename': safe_filename})
    
    except Exception:
        transfer_app.log_status("Upload error occurred")
        return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/send_file', methods=['POST'])
def send_file():
    try:
        # Rate limiting
        client_ip = get_client_ip()
        content_length = request.content_length or 0
        
        if not rate_limiter.is_allowed(client_ip, content_length):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Authentication check
        if not check_authentication(transfer_app.password):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
            
        target_device = data.get('device')
        file_data = data.get('file_data')
        filename = data.get('filename')
        
        if not all([target_device, file_data, filename]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate target device format
        validated_device = validate_ip_port(target_device)
        if not validated_device:
            return jsonify({'error': 'Invalid target device format'}), 400
        
        # Sanitize filename
        safe_filename = sanitize_filename(filename)
        
        # Validate file data (base64)
        if not isinstance(file_data, str):
            return jsonify({'error': 'Invalid file data format'}), 400
        
        # Decode base64 file data
        import base64
        try:
            file_content = base64.b64decode(file_data)
        except Exception:
            return jsonify({'error': 'Invalid base64 data'}), 400
        
        # Check file size
        if len(file_content) > 100 * 1024 * 1024:  # 100MB limit
            return jsonify({'error': 'File too large'}), 400
        
        # Prepare multipart form data
        boundary = '----WebKitFormBoundary' + hashlib.md5(str(time.time()).encode()).hexdigest()
        body = f'--{boundary}\r\n'
        body += f'Content-Disposition: form-data; name="file"; filename="{safe_filename}"\r\n'
        body += 'Content-Type: application/octet-stream\r\n\r\n'
        body = body.encode() + file_content + f'\r\n--{boundary}--\r\n'.encode()
        
        # Send to target device
        url = f"http://{validated_device}/upload"
        req = urllib.request.Request(url, data=body)
        req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
        
        # Add authentication if password is set
        if transfer_app.password:
            req.add_header('Authorization', f'Bearer {transfer_app.password}')
        
        with urllib.request.urlopen(req, timeout=30) as response:
            transfer_app.log_status(f"File sent successfully: {safe_filename} to {validated_device}")
            return jsonify({'success': True})
    
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return jsonify({'error': 'Authentication failed'}), 401
        elif e.code == 429:
            return jsonify({'error': 'Rate limit exceeded'}), 429
        else:
            return jsonify({'error': 'Failed to send file'}), 500
    except Exception:
        transfer_app.log_status("Network error occurred")
        return jsonify({'error': 'Send failed'}), 500

@app.route('/api/send_message', methods=['POST'])
def send_message():
    try:
        # Rate limiting
        client_ip = get_client_ip()
        if not rate_limiter.is_allowed(client_ip):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Authentication check
        if not check_authentication(transfer_app.password):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
            
        target_device = data.get('device')
        message = data.get('message')
        
        if not all([target_device, message]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate target device format
        validated_device = validate_ip_port(target_device)
        if not validated_device:
            return jsonify({'error': 'Invalid target device format'}), 400
        
        # Sanitize message
        sanitized_message = sanitize_text_message(message)
        if not sanitized_message:
            return jsonify({'error': 'Invalid message content'}), 400
        
        def send_async():
            try:
                # Create message data for Socket.IO
                message_data = {
                    'text': sanitized_message,
                    'auth': transfer_app.password if transfer_app.password else None
                }
                
                # Send HTTP POST to target device's Socket.IO message endpoint
                url = f"http://{validated_device}/api/receive_message"
                payload = json.dumps(message_data)
                
                req = urllib.request.Request(url, data=payload.encode('utf-8'))
                req.add_header('Content-Type', 'application/json')
                
                # Add authentication if password is set
                if transfer_app.password:
                    req.add_header('Authorization', f'Bearer {transfer_app.password}')
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    transfer_app.log_status(f"Sent message to {validated_device}: {sanitized_message[:50]}...")
                    
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    transfer_app.log_status("Authentication failed")
                else:
                    transfer_app.log_status(f"HTTP error: {e.code}")
            except urllib.error.URLError:
                transfer_app.log_status("Connection failed")
            except Exception:
                transfer_app.log_status("Failed to send message")
        
        threading.Thread(target=send_async, daemon=True).start()
        return jsonify({'success': True})
    
    except Exception:
        return jsonify({'error': 'Send failed'}), 500

@app.route('/api/receive_message', methods=['POST'])
def receive_message():
    """Handle incoming messages from other devices via HTTP"""
    try:
        # Rate limiting
        client_ip = get_client_ip()
        if not rate_limiter.is_allowed(client_ip):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Authentication check
        if not check_authentication(transfer_app.password):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        message_text = data.get('text', '')
        auth = data.get('auth')
        
        # Additional auth check from message data
        if transfer_app.password and auth != transfer_app.password:
            return jsonify({'error': 'Invalid authentication'}), 401
        
        # Sanitize and broadcast message
        sanitized_text = sanitize_text_message(message_text)
        if sanitized_text:
            socketio.emit('message_received', {
                'message': sanitized_text,
                'timestamp': time.strftime('%H:%M:%S')
            })
            transfer_app.log_status(f"Received message from {client_ip}: {sanitized_text[:50]}...")
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Invalid message content'}), 400
            
    except Exception:
        return jsonify({'error': 'Failed to process message'}), 500

@app.route('/downloads/<path:filename>')
def download_file(filename):
    try:
        # Rate limiting
        client_ip = get_client_ip()
        if not rate_limiter.is_allowed(client_ip):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Authentication check
        if not check_authentication(transfer_app.password):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(filename)
        file_path = transfer_app.downloads_dir / safe_filename
        
        # Ensure file exists and is within downloads directory
        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404
            
        if not str(file_path.resolve()).startswith(str(transfer_app.downloads_dir.resolve())):
            return jsonify({'error': 'Access denied'}), 403
        
        return send_from_directory(transfer_app.downloads_dir, safe_filename)
    
    except Exception:
        return jsonify({'error': 'Download failed'}), 500

@socketio.on('connect')
def handle_connect():
    emit('status_update', {
        'timestamp': time.strftime('%H:%M:%S'),
        'message': 'Connected to TransferD'
    })

@socketio.on('message_text')
def handle_message_text(data):
    """Handle incoming text messages from Socket.IO clients"""
    try:
        # Rate limiting
        client_ip = get_client_ip()
        if not rate_limiter.is_allowed(client_ip):
            emit('error', {'message': 'Rate limit exceeded'})
            return
        
        # Authentication check
        if transfer_app.password:
            auth = data.get('auth')
            if auth != transfer_app.password:
                emit('error', {'message': 'Authentication required'})
                return
        
        # Get and sanitize message text
        message_text = data.get('text', '')
        sanitized_text = sanitize_text_message(message_text)
        
        if sanitized_text:
            # Broadcast received message to all clients
            socketio.emit('message_received', {
                'message': sanitized_text,
                'timestamp': time.strftime('%H:%M:%S')
            })
            transfer_app.log_status(f"Received message: {sanitized_text[:50]}...")
        else:
            emit('error', {'message': 'Invalid message content'})
            
    except Exception as e:
        transfer_app.log_status(f"Error handling message: {str(e)}")
        emit('error', {'message': 'Failed to process message'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=False)