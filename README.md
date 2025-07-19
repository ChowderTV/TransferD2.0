# TransferD - Local Network File Transfer

A simple, secure local network file and message transfer application. Available in both desktop GUI and modern web-based versions.

## 🚀 Quick Start (Web Version - Recommended)

### Docker Deployment (Easiest)
```bash
# Download docker-compose.yml
curl -O https://raw.githubusercontent.com/ChowderTV/TransferD2.0/main/docker-compose.yml

# Deploy with Docker Compose
docker-compose up -d

# Access from any browser
open http://localhost:8080
```

### One-Line Deployment
```bash
curl -sSL https://raw.githubusercontent.com/ChowderTV/TransferD2.0/main/docker-compose.yml | docker-compose -f - up -d
```

### Manual Web Setup
```bash
# Install dependencies
pip install -r requirements-docker.txt

# Run web application
python app.py

# Access from browser: http://localhost:8080
```

## 🖥️ Desktop Version (Legacy)

### Using the run script
```bash
./run.sh
```

### Manual desktop setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run desktop application
python3 transfer_app.py
```

## ✨ Features

- 🌐 **Web Interface**: Modern responsive design accessible from any browser
- 📱 **Mobile Friendly**: Works on phones, tablets, and desktops
- 🔄 **File Transfer**: Drag & drop files between devices on same network
- 💬 **Real-time Messaging**: Instant text/link sharing with WebSocket
- 🎯 **Auto-discovery**: Devices automatically find each other via mDNS
- 🔒 **Security**: Optional password protection and encrypted messages
- 🐳 **Docker Ready**: Easy deployment with automatic updates
- 📊 **Progress Tracking**: Real-time transfer progress and status
- 🚫 **No Cloud**: Completely local network - no external services
- 📏 **100MB Limit**: Optimized for quick file sharing

## 📖 How to Use

### Web Version
1. **Deploy**: Run `docker-compose up -d` or `python app.py`
2. **Access**: Open `http://localhost:8080` in any browser
3. **Mobile Access**: Use your computer's IP address from phones/tablets
4. **Transfer Files**: Drag & drop files or click upload area
5. **Send Messages**: Type in message box and click "Send Text"
6. **Device Discovery**: Devices appear automatically in left panel
7. **Manual Connection**: Enter IP:Port if auto-discovery fails

### Desktop Version
1. **Launch**: Run `./run.sh` or `python transfer_app.py`
2. **Device Discovery**: Devices auto-discover via mDNS
3. **Select Device**: Click device in list to select
4. **Transfer**: Drag & drop files or browse to select
5. **Message**: Type text/links and send

## 🏗️ Architecture

### Web Version (Recommended)
- **Frontend**: HTML5/CSS3/JavaScript with responsive design
- **Backend**: Flask with SocketIO for real-time updates
- **File Transfer**: HTTP multipart upload with progress tracking
- **Messaging**: WebSocket for instant communication
- **Discovery**: Zeroconf/mDNS for automatic device detection
- **Deployment**: Docker containerized with health checks

### Desktop Version (Legacy)
- **GUI**: tkinter with modern dark theme
- **File Transfer**: HTTP server for uploads
- **Messaging**: WebSocket for real-time text messages
- **Discovery**: Zeroconf/mDNS for automatic device discovery

## 📁 File Structure

```
TransferD2.0/
├── app.py                    # Web application (Flask)
├── transfer_app.py           # Desktop application (tkinter)
├── templates/
│   └── index.html           # Web interface template
├── static/
│   ├── style.css            # Web interface styling
│   └── app.js               # Web interface JavaScript
├── requirements-docker.txt   # Web version dependencies
├── requirements.txt         # Desktop version dependencies
├── Dockerfile               # Container build instructions
├── docker-compose.yml       # Easy deployment configuration
├── .dockerignore           # Docker build optimization
├── run.sh                  # Desktop version launcher
└── README-DOCKER.md        # Detailed Docker guide
```

## 🔧 Requirements

### Web Version
- **Docker**: For containerized deployment (recommended)
- **Python 3.11+**: For manual deployment
- **Network**: Local network connection
- **Browser**: Any modern web browser

### Desktop Version
- **Python 3.7+**: Required runtime
- **GUI Support**: X11/Wayland on Linux, built-in on Windows/Mac
- **Network**: Local network connection

## ⚡ Advantages of Web Version

| Feature | Web Version | Desktop Version |
|---------|-------------|-----------------|
| **Cross-platform** | ✅ Any browser | ❌ OS-specific GUI |
| **Mobile Support** | ✅ Responsive design | ❌ Desktop only |
| **Easy Updates** | ✅ Rebuild container | ❌ Manual redistribution |
| **No Installation** | ✅ Just open browser | ❌ Python + deps required |
| **Remote Access** | ✅ Any network device | ❌ Local desktop only |
| **Modern UI** | ✅ CSS3 + animations | ❌ Limited tkinter styling |

## 🐳 Docker Registry Details

**Image Location**: `ghcr.io/chowdertv/transferd2.0:latest`  
**Registry**: GitHub Container Registry (ghcr.io)  
**Supported Platforms**: linux/amd64, linux/arm64  
**Auto-builds**: Triggered on every push to main branch  

### Available Tags:
- `latest` - Latest stable release from main branch
- `v2.x.x` - Specific version releases
- `main` - Development branch builds

### Manual Docker Run:
```bash
docker run -d \
  --name transferd \
  -p 8080:8080 \
  -p 8081:8081 \
  -v ./downloads:/app/downloads \
  ghcr.io/chowdertv/transferd2.0:latest
```

## 🚨 Troubleshooting

### Web Version
- **Can't access**: Check firewall allows ports 8080/8081
- **Mobile issues**: Use computer's IP, not `localhost`
- **Upload fails**: Check file size under 100MB
- **Docker issues**: Run `docker-compose logs transferd`
- **Image pull fails**: Ensure internet connection for registry access

### Desktop Version
- **No drag & drop**: Install `tkinterdnd2` or click to browse
- **Discovery fails**: Enter IP:Port manually
- **GUI issues**: Ensure X11 forwarding on Linux

### Common Issues
- **Network discovery**: Ensure mDNS/Bonjour enabled
- **File permissions**: Check downloads directory writable
- **Port conflicts**: Change ports in configuration files

## 🔒 Security Notes

- **Local Network Only**: No internet connectivity required or used
- **Password Protection**: Optional password for sensitive environments
- **Encrypted Messaging**: Text messages use Fernet encryption
- **File Security**: Files transferred unencrypted (local network assumption)
- **Container Security**: Runs as non-root user in Docker

## 📊 Performance

- **File Transfer**: Full network speed (typically 100-1000 Mbps)
- **Memory Usage**: ~50MB for web version, ~30MB for desktop
- **Startup Time**: ~5 seconds for web, ~2 seconds for desktop
- **File Size Limit**: 100MB (configurable)
- **Concurrent Users**: Unlimited (network bandwidth dependent)