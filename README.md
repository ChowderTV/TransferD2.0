# TransferD - Local Network File Transfer

A simple, secure local network file and message transfer application.

## Features

- 🔄 Transfer files and text between devices on the same network
- 🎯 Auto-discover devices using mDNS/Zeroconf
- 🖱️ Drag & drop file support (with tkinterdnd2)
- 🔒 Optional password protection
- 🔐 Encrypted text messages
- 📊 Real-time transfer progress
- 🚫 No external dependencies or cloud services
- 📏 100MB file size limit

## Quick Start

### Option 1: Using the run script
```bash
./run.sh
```

### Option 2: Manual setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python3 transfer_app.py
```

## How to Use

1. **Launch the application** on multiple devices on the same network
2. **Device Discovery**: Devices should auto-discover each other via mDNS
3. **Manual Connection**: Enter IP:Port manually if auto-discovery fails
4. **Select Device**: Click on a device in the list to select it
5. **Send Files**: 
   - Drag & drop files onto the drop area, or
   - Click the drop area to browse for files
6. **Send Messages**: Type text/links and click "Send Text"
7. **Password Protection**: Optionally set a password for added security

## Technical Details

- **GUI**: tkinter with modern dark theme
- **File Transfer**: HTTP server for file uploads
- **Messaging**: WebSocket for real-time text messages
- **Discovery**: Zeroconf/mDNS for automatic device discovery
- **Security**: Fernet encryption for text messages
- **Network**: Local network only (no internet connectivity)

## File Structure

- `transfer_app.py` - Main application
- `requirements.txt` - Python dependencies
- `run.sh` - Convenience script to run the app
- `venv/` - Python virtual environment

## Requirements

- Python 3.7+
- Local network connection
- GUI support (X11/Wayland on Linux, built-in on Windows/Mac)

## Limitations

- 100MB maximum file size
- Local network only
- Requires GUI environment
- Text messages are encrypted but files are not

## Troubleshooting

- If drag & drop doesn't work, click the file area to browse instead
- If auto-discovery fails, manually enter the IP address and port
- Default port is 8080 (HTTP) and 8081 (WebSocket)
- Files are saved to `~/Downloads/TransferD/`