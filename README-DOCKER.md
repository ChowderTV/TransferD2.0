# TransferD Web - Docker Deployment Guide

## Overview
TransferD has been converted to a modern web-based application with Docker support for easy deployment. The web interface maintains all the original functionality while adding cross-platform browser access.

## Features
- **Web-based GUI**: Modern responsive interface accessible from any browser
- **Cross-platform**: Works on phones, tablets, desktops
- **Auto-updates**: Simply rebuild container for updates
- **Easy deployment**: One command Docker setup
- **Mobile-friendly**: Responsive design for all screen sizes

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Ports 8080 and 8081 available

### Deployment

1. **Build and run with Docker Compose (Recommended):**
```bash
docker-compose up -d
```

2. **Or build and run manually:**
```bash
# Build the image
docker build -t transferd-web .

# Run the container
docker run -d \
  --name transferd \
  -p 8080:8080 \
  -p 8081:8081 \
  -v ./downloads:/app/downloads \
  transferd-web
```

3. **Access the application:**
   - Open your browser to `http://localhost:8080`
   - Or access from any device on your network: `http://YOUR-IP:8080`

## Usage

### Web Interface
- **Device Discovery**: Devices automatically appear in the left panel
- **Manual Device Addition**: Enter IP:Port and click "Add"
- **File Transfer**: Drag & drop files or click the upload area
- **Messaging**: Type messages and click "Send Text"
- **Password Protection**: Set optional password for security

### From Other Devices
- Access `http://YOUR-DOCKER-HOST-IP:8080` from any browser
- Mobile devices can bookmark the page for easy access

## File Management

### Downloads Location
- Files are saved to `./downloads/` directory
- This is mounted as a Docker volume for persistence
- Files persist even when container is restarted

### File Size Limit
- Maximum file size: 100MB
- Large files show progress indicators
- Mobile-optimized for smaller files

## Network Configuration

### Ports
- **8080**: Web interface (HTTP)
- **8081**: WebSocket for messaging
- Both ports must be accessible for full functionality

### Device Discovery
- Uses mDNS/Zeroconf for automatic device discovery
- Works across Docker networks and host networks
- Manual IP entry available if auto-discovery fails

## Management Commands

### View logs:
```bash
docker-compose logs -f transferd
```

### Stop application:
```bash
docker-compose down
```

### Update application:
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose up -d --build
```

### Remove all data:
```bash
docker-compose down -v
rm -rf downloads/
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Change ports in `docker-compose.yml`
2. **Permission issues**: Check `downloads/` directory permissions
3. **Network discovery**: Ensure Docker container can access host network
4. **Mobile access**: Use computer's IP address, not `localhost`

### Debug Mode
```bash
# Run with debug output
docker-compose up
```

### Health Check
```bash
# Check container health
docker-compose ps

# Test web interface
curl http://localhost:8080
```

## Advanced Configuration

### Environment Variables
```yaml
environment:
  - PYTHONUNBUFFERED=1
  - FLASK_ENV=production
  - MAX_FILE_SIZE=104857600  # 100MB in bytes
```

### Custom Network
```yaml
networks:
  transferd-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Persistent Storage
```yaml
volumes:
  - ./downloads:/app/downloads
  - ./config:/app/config  # For future config files
```

## Security Considerations

- Application runs as non-root user inside container
- Password protection available for sensitive environments
- Local network only - no external internet access required
- All file transfers are local network only

## Migration from Original App

The web version provides the same functionality as the original tkinter app:

| Original Feature | Web Equivalent |
|-----------------|----------------|
| Desktop GUI | Browser interface |
| Drag & drop | Web drag & drop |
| Device list | Device panel |
| Status log | Real-time status updates |
| File transfer | HTTP upload with progress |
| Messaging | WebSocket messaging |
| Auto-discovery | mDNS discovery |

## Performance

- **Startup time**: ~5 seconds
- **File transfer**: Full network speed
- **Memory usage**: ~50MB per container
- **CPU usage**: Minimal when idle

## Support

For issues or questions:
1. Check logs: `docker-compose logs transferd`
2. Verify network connectivity
3. Test with simple file transfers first
4. Check firewall settings for ports 8080/8081