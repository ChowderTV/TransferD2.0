// TransferD Web Interface JavaScript
class TransferDApp {
    constructor() {
        this.socket = null;
        this.selectedDevice = null;
        this.devices = [];
        
        this.initializeElements();
        this.initializeSocketIO();
        this.bindEvents();
        this.loadDevices();
        this.loadMessageHistory();
    }
    
    initializeElements() {
        // Device elements
        this.deviceList = document.getElementById('device-list');
        this.ipInput = document.getElementById('ip-input');
        this.addDeviceBtn = document.getElementById('add-device-btn');
        this.passwordInput = document.getElementById('password-input');
        this.setPasswordBtn = document.getElementById('set-password-btn');
        
        // Transfer elements
        this.messageInput = document.getElementById('message-input');
        this.sendMessageBtn = document.getElementById('send-message-btn');
        this.dropArea = document.getElementById('drop-area');
        this.fileInput = document.getElementById('file-input');
        
        // Status elements
        this.statusLog = document.getElementById('status-log');
        
        // Modal elements
        this.messageModal = document.getElementById('message-modal');
        this.closeModal = document.getElementById('close-modal');
        this.receivedMessage = document.getElementById('received-message');
        this.messageTimestamp = document.getElementById('message-timestamp');
        
        // Progress elements
        this.progressContainer = document.getElementById('progress-container');
        this.progressFill = document.getElementById('progress-fill');
        this.progressText = document.getElementById('progress-text');
        
        // Toast container
        this.toastContainer = document.getElementById('toast-container');
    }
    
    initializeSocketIO() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            this.showToast('Connected to TransferD', 'success');
            this.loadMessageHistory(); // Reload messages on reconnect
        });
        
        this.socket.on('device_discovered', (data) => {
            this.addDevice(data.device);
        });
        
        this.socket.on('status_update', (data) => {
            this.logStatus(data.message, data.timestamp);
        });
        
        this.socket.on('message_received', (data) => {
            this.showReceivedMessage(data.message, data.timestamp);
        });
        
        this.socket.on('disconnect', () => {
            this.showToast('Disconnected from server', 'error');
        });
        
        this.socket.on('error', (data) => {
            this.showToast(data.message || 'Socket error', 'error');
        });
    }
    
    bindEvents() {
        // Device management
        this.addDeviceBtn.addEventListener('click', () => this.addManualDevice());
        this.ipInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.addManualDevice();
        });
        this.setPasswordBtn.addEventListener('click', () => this.setPassword());
        this.passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.setPassword();
        });
        
        // Message sending
        this.sendMessageBtn.addEventListener('click', () => this.sendMessage());
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && e.ctrlKey) this.sendMessage();
        });
        
        // File handling
        this.dropArea.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        
        // Drag and drop
        this.dropArea.addEventListener('dragover', (e) => this.handleDragOver(e));
        this.dropArea.addEventListener('dragleave', (e) => this.handleDragLeave(e));
        this.dropArea.addEventListener('drop', (e) => this.handleDrop(e));
        
        // Modal
        this.closeModal.addEventListener('click', () => this.hideMessageModal());
        this.messageModal.addEventListener('click', (e) => {
            if (e.target === this.messageModal) this.hideMessageModal();
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.hideMessageModal();
        });
    }
    
    async loadDevices() {
        try {
            const response = await fetch('/api/devices');
            const data = await response.json();
            this.devices = data.devices;
            this.updateDeviceList();
        } catch (error) {
            this.showToast('Error loading devices', 'error');
        }
    }
    
    updateDeviceList() {
        this.deviceList.innerHTML = '';
        this.devices.forEach(device => {
            this.addDeviceToList(device);
        });
    }
    
    addDevice(device) {
        if (!this.devices.includes(device)) {
            this.devices.push(device);
            this.addDeviceToList(device);
            this.showToast(`Device discovered: ${device}`, 'info');
        }
    }
    
    addDeviceToList(device) {
        const li = document.createElement('li');
        li.className = 'device-item';
        li.innerHTML = `
            <span>${device}</span>
            <div class="device-status"></div>
        `;
        
        li.addEventListener('click', () => this.selectDevice(device, li));
        this.deviceList.appendChild(li);
    }
    
    selectDevice(device, element) {
        // Remove previous selection
        document.querySelectorAll('.device-item').forEach(item => {
            item.classList.remove('selected');
        });
        
        // Select new device
        element.classList.add('selected');
        this.selectedDevice = device;
        this.logStatus(`Selected device: ${device}`);
    }
    
    async addManualDevice() {
        const device = this.ipInput.value.trim();
        if (!device || device === 'Enter IP:Port') return;
        
        try {
            const response = await fetch('/api/devices', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ device })
            });
            
            const data = await response.json();
            if (data.success) {
                this.addDevice(data.device);
                this.ipInput.value = '';
                this.ipInput.placeholder = 'Enter IP:Port';
            } else {
                this.showToast(data.error || 'Failed to add device', 'error');
            }
        } catch (error) {
            this.showToast('Error adding device', 'error');
        }
    }
    
    async setPassword() {
        const password = this.passwordInput.value.trim();
        
        try {
            const response = await fetch('/api/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            
            if (response.ok) {
                this.passwordInput.value = '';
                this.passwordInput.placeholder = 'Optional Password';
                this.showToast(password ? 'Password set' : 'Password cleared', 'success');
            }
        } catch (error) {
            this.showToast('Error setting password', 'error');
        }
    }
    
    async sendMessage() {
        if (!this.selectedDevice) {
            this.showToast('Please select a device first', 'error');
            return;
        }
        
        const message = this.messageInput.value.trim();
        if (!message) return;
        
        try {
            const response = await fetch('/api/send_message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device: this.selectedDevice,
                    message: message
                })
            });
            
            const data = await response.json();
            if (data.success) {
                this.messageInput.value = '';
                this.showToast('Message sent', 'success');
            } else {
                this.showToast(data.error || 'Failed to send message', 'error');
            }
        } catch (error) {
            this.showToast('Error sending message', 'error');
        }
    }
    
    handleFileSelect(event) {
        const files = event.target.files;
        if (files.length > 0) {
            this.processFiles(files);
        }
    }
    
    handleDragOver(event) {
        event.preventDefault();
        this.dropArea.classList.add('drag-over');
    }
    
    handleDragLeave(event) {
        event.preventDefault();
        this.dropArea.classList.remove('drag-over');
    }
    
    handleDrop(event) {
        event.preventDefault();
        this.dropArea.classList.remove('drag-over');
        
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            this.processFiles(files);
        }
    }
    
    async processFiles(files) {
        if (!this.selectedDevice) {
            this.showToast('Please select a device first', 'error');
            return;
        }
        
        for (let file of files) {
            if (file.size > 100 * 1024 * 1024) { // 100MB limit
                this.showToast(`File too large: ${file.name} (${(file.size/1024/1024).toFixed(1)}MB)`, 'error');
                continue;
            }
            
            await this.sendFile(file);
        }
    }
    
    async sendFile(file) {
        this.showProgress(`Sending ${file.name}...`);
        
        try {
            // Convert file to base64
            const fileData = await this.fileToBase64(file);
            
            const response = await fetch('/api/send_file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device: this.selectedDevice,
                    filename: file.name,
                    file_data: fileData
                })
            });
            
            const data = await response.json();
            if (data.success) {
                this.showToast(`File sent: ${file.name}`, 'success');
            } else {
                this.showToast(data.error || 'Failed to send file', 'error');
            }
        } catch (error) {
            this.showToast(`Error sending file: ${error.message}`, 'error');
        } finally {
            this.hideProgress();
        }
    }
    
    fileToBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => {
                const base64 = reader.result.split(',')[1];
                resolve(base64);
            };
            reader.onerror = error => reject(error);
        });
    }
    
    showProgress(text) {
        this.progressText.textContent = text;
        this.progressContainer.style.display = 'block';
        this.progressFill.style.width = '0%';
        
        // Simulate progress
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 90) progress = 90;
            this.progressFill.style.width = progress + '%';
            
            if (progress >= 90) {
                clearInterval(interval);
            }
        }, 200);
    }
    
    hideProgress() {
        this.progressFill.style.width = '100%';
        setTimeout(() => {
            this.progressContainer.style.display = 'none';
        }, 500);
    }
    
    showReceivedMessage(message, timestamp) {
        this.receivedMessage.textContent = message;
        this.messageTimestamp.textContent = `Received at ${timestamp}`;
        this.messageModal.style.display = 'block';
        this.showToast('New message received', 'info');
    }
    
    hideMessageModal() {
        this.messageModal.style.display = 'none';
    }
    
    logStatus(message, timestamp = null) {
        const time = timestamp || new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'status-entry';
        entry.innerHTML = `
            <span class="status-timestamp">${time}</span>
            <span class="status-message">${message}</span>
        `;
        
        this.statusLog.appendChild(entry);
        this.statusLog.scrollTop = this.statusLog.scrollHeight;
        
        // Limit status entries
        while (this.statusLog.children.length > 100) {
            this.statusLog.removeChild(this.statusLog.firstChild);
        }
    }
    
    async loadMessageHistory() {
        try {
            const response = await fetch('/api/messages/history?limit=10');
            if (response.ok) {
                const data = await response.json();
                data.messages.forEach(msg => {
                    this.logStatus(`📨 ${msg.content.substring(0, 50)}${msg.content.length > 50 ? '...' : ''} (from ${msg.sender_ip})`, 
                                 new Date(msg.timestamp).toLocaleTimeString());
                });
                if (data.messages.length > 0) {
                    this.logStatus(`Loaded ${data.messages.length} recent messages`);
                }
            }
        } catch (error) {
            console.log('Could not load message history:', error);
        }
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        this.toastContainer.appendChild(toast);
        
        // Auto remove after 4 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 4000);
        
        // Make it clickable to dismiss
        toast.addEventListener('click', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.transferApp = new TransferDApp();
});

// Handle placeholder text
document.addEventListener('DOMContentLoaded', () => {
    const ipInput = document.getElementById('ip-input');
    const passwordInput = document.getElementById('password-input');
    
    ipInput.addEventListener('focus', () => {
        if (ipInput.value === 'Enter IP:Port') {
            ipInput.value = '';
        }
    });
    
    ipInput.addEventListener('blur', () => {
        if (ipInput.value === '') {
            ipInput.value = 'Enter IP:Port';
        }
    });
    
    passwordInput.addEventListener('focus', () => {
        if (passwordInput.placeholder === 'Optional Password') {
            passwordInput.placeholder = '';
        }
    });
    
    passwordInput.addEventListener('blur', () => {
        if (passwordInput.value === '') {
            passwordInput.placeholder = 'Optional Password';
        }
    });
});