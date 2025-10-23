# 🚀 Detailed Run Instructions for Cybersecurity System

## 📋 Prerequisites

Before running the project, ensure you have the following installed:

### Required Software
- **Python 3.8 or higher** - [Download Python](https://www.python.org/downloads/)
- **Redis Server** - [Download Redis](https://redis.io/download)
- **Git** - [Download Git](https://git-scm.com/downloads)

### Optional Software
- **Docker & Docker Compose** - [Download Docker](https://www.docker.com/get-started)
- **PostgreSQL** - [Download PostgreSQL](https://www.postgresql.org/download/)

### System Requirements
- **Operating System**: Windows, macOS, or Linux
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: At least 2GB free space
- **Network**: Internet connection for downloading dependencies

## 🔧 Installation Methods

### Method 1: Local Installation (Recommended for Development)

#### Step 1: Clone the Repository
```bash
# Navigate to your desired directory
cd /path/to/your/projects

# Clone the repository
git clone <your-repository-url>
cd tahaproject
```

#### Step 2: Create Python Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

#### Step 3: Install Python Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install project dependencies
pip install -r requirements.txt
```

#### Step 4: Install and Start Redis
```bash
# On Windows (using Chocolatey):
choco install redis-64

# On macOS (using Homebrew):
brew install redis

# On Ubuntu/Debian:
sudo apt update
sudo apt install redis-server

# Start Redis server
redis-server
```

#### Step 5: Configure Environment Variables
```bash
# Copy the example environment file
cp config/env_example.txt .env

# Edit the .env file with your preferred editor
# Windows:
notepad .env

# macOS/Linux:
nano .env
```

**Important Environment Variables to Configure:**
```env
# Database settings (optional)
DATABASE_URL="postgresql://user:password@localhost:5432/cybersecurity_db"

# Redis settings
REDIS_URL="redis://localhost:6379/0"

# Security settings
SECRET_KEY="your-secret-key-change-this-in-production"

# AI Model settings
MODEL_PATH="models/"

# Network monitoring
MONITOR_INTERFACES="eth0,wlan0"

# Threat detection thresholds
THREAT_THRESHOLD=0.7
ANOMALY_THRESHOLD=0.8

# Alerting settings
ALERT_EMAIL_ENABLED=true
ALERT_SLACK_ENABLED=false
```

#### Step 6: Create Necessary Directories
```bash
# Create required directories
mkdir -p logs models data

# Set permissions (Linux/macOS)
chmod 755 logs models data
```

#### Step 7: Run the Application
```bash
# Method 1: Using the run script (recommended)
python run.py

# Method 2: Direct execution
python main.py

# Method 3: Using uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Method 2: Docker Installation (Recommended for Production)

#### Step 1: Clone the Repository
```bash
git clone <your-repository-url>
cd tahaproject
```

#### Step 2: Build and Run with Docker Compose
```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

#### Step 3: Access the Application
```bash
# Check if services are running
docker-compose ps

# Access the dashboard
open http://localhost:8000
```

## 🖥️ Running the System

### Starting the Application

#### Option 1: Quick Start (Recommended)
```bash
# Navigate to project directory
cd /Users/axelerant/Documents/tahaproject

# Start Redis (in a separate terminal)
redis-server

# Run the application
python run.py
```

#### Option 2: Manual Start
```bash
# Start Redis server
redis-server

# In another terminal, start the application
python main.py
```

#### Option 3: Development Mode
```bash
# Start with auto-reload for development
uvicorn main:app --host 0.0.0.0 --port 8000 --reload --log-level debug
```

### Verifying the Installation

#### Check System Status
```bash
# Health check
curl http://localhost:8000/health

# System status
curl http://localhost:8000/api/v1/status

# Performance metrics
curl http://localhost:8000/api/v1/performance
```

#### Access the Dashboard
1. Open your web browser
2. Navigate to: `http://localhost:8000`
3. You should see the cybersecurity dashboard

## 🔍 Troubleshooting

### Common Issues and Solutions

#### Issue 1: Redis Connection Failed
```bash
# Error: Redis connection failed
# Solution: Start Redis server
redis-server

# Check if Redis is running
redis-cli ping
# Should return: PONG
```

#### Issue 2: Permission Denied for Network Monitoring
```bash
# Error: Permission denied for packet capture
# Solution: Run with appropriate permissions

# On Linux/macOS:
sudo python main.py

# Or configure network interfaces:
sudo setcap cap_net_raw,cap_net_admin+eip $(which python)
```

#### Issue 3: Missing Dependencies
```bash
# Error: ModuleNotFoundError
# Solution: Install missing dependencies
pip install -r requirements.txt

# If specific package fails:
pip install --upgrade pip
pip install <package-name>
```

#### Issue 4: Port Already in Use
```bash
# Error: Port 8000 already in use
# Solution: Use a different port
uvicorn main:app --host 0.0.0.0 --port 8001

# Or kill the process using the port
# On Linux/macOS:
lsof -ti:8000 | xargs kill -9

# On Windows:
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

#### Issue 5: Docker Issues
```bash
# Error: Docker daemon not running
# Solution: Start Docker Desktop

# Error: Port conflicts
# Solution: Stop conflicting services
docker-compose down
docker system prune -f
docker-compose up -d
```

### System Requirements Check

#### Check Python Version
```bash
python --version
# Should be 3.8 or higher
```

#### Check Redis Installation
```bash
redis-server --version
redis-cli --version
```

#### Check Network Interfaces
```bash
# On Linux/macOS:
ifconfig

# On Windows:
ipconfig
```

## 📊 Monitoring and Maintenance

### Viewing Logs
```bash
# Application logs
tail -f logs/cybersecurity_system.log

# Docker logs
docker-compose logs -f cybersecurity-system

# System logs (Linux)
journalctl -u redis -f
```

### Performance Monitoring
```bash
# Check system resources
htop  # or top on Linux/macOS
# Task Manager on Windows

# Check Redis memory usage
redis-cli info memory

# Check application metrics
curl http://localhost:8000/api/v1/performance
```

### Backup and Recovery
```bash
# Backup Redis data
redis-cli BGSAVE

# Backup application data
tar -czf backup-$(date +%Y%m%d).tar.gz logs/ models/ data/

# Restore from backup
tar -xzf backup-YYYYMMDD.tar.gz
```

## 🔧 Configuration

### Network Monitoring Configuration
```python
# In config/settings.py or .env file
MONITOR_INTERFACES="eth0,wlan0"  # Network interfaces to monitor
PACKET_CAPTURE_TIMEOUT=30        # Packet capture timeout in seconds
MAX_PACKET_SIZE=65536           # Maximum packet size
```

### AI Model Configuration
```python
THREAT_THRESHOLD=0.7            # Threat detection threshold
ANOMALY_THRESHOLD=0.8           # Anomaly detection threshold
MAX_CONCURRENT_ANALYSES=10      # Maximum concurrent analyses
```

### Alerting Configuration
```python
ALERT_EMAIL_ENABLED=true        # Enable email alerts
ALERT_SLACK_ENABLED=false       # Enable Slack alerts
ALERT_COOLDOWN=300              # Alert cooldown in seconds
```

## 🚀 Production Deployment

### Environment Setup
```bash
# Set production environment
export ENVIRONMENT=production

# Use production configuration
cp config/production.env .env

# Start with production settings
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Security Considerations
```bash
# Change default secret key
export SECRET_KEY="your-secure-secret-key"

# Use HTTPS in production
# Configure SSL certificates
# Set up firewall rules
# Enable authentication
```

### Scaling
```bash
# Use multiple workers
uvicorn main:app --workers 4

# Use Docker Swarm or Kubernetes
docker stack deploy -c docker-compose.yml cybersecurity

# Set up load balancer
# Configure Redis clustering
# Use external database
```

## 📞 Support

### Getting Help
1. **Check the logs** for error messages
2. **Review the documentation** in the `docs/` directory
3. **Check system requirements** and dependencies
4. **Verify configuration** settings
5. **Test individual components** separately

### Useful Commands
```bash
# Check system status
curl http://localhost:8000/health

# View recent events
curl http://localhost:8000/api/v1/events

# Check threat statistics
curl http://localhost:8000/api/v1/threat-stats

# View performance metrics
curl http://localhost:8000/api/v1/performance
```

### Contact Information
- **Documentation**: Check `docs/` directory
- **Issues**: Report bugs and feature requests
- **Development**: Follow contributing guidelines

## ✅ Success Checklist

After following these instructions, you should have:

- [ ] Python 3.8+ installed and working
- [ ] Redis server running and accessible
- [ ] All Python dependencies installed
- [ ] Environment variables configured
- [ ] Application starting without errors
- [ ] Dashboard accessible at http://localhost:8000
- [ ] API endpoints responding correctly
- [ ] Network monitoring active
- [ ] Threat detection working
- [ ] Alerts being generated

If all items are checked, your cybersecurity system is running successfully! 🎉
