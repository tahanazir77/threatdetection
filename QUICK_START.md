# ⚡ Quick Start Guide

## 🚀 Get Running in 5 Minutes

### Prerequisites Check
```bash
# Check Python version (should be 3.8+)
python --version

# Check if Redis is installed
redis-server --version
```

### Step 1: Install Dependencies
```bash
# Navigate to project directory
cd /Users/axelerant/Documents/tahaproject

# Install Python packages
pip install -r requirements.txt
```

### Step 2: Start Redis
```bash
# Start Redis server (in a separate terminal)
redis-server
```

### Step 3: Run the Application
```bash
# Start the cybersecurity system
python run.py
```

### Step 4: Access Dashboard
Open your browser and go to: **http://localhost:8000**

## 🔧 Alternative: Docker Quick Start

```bash
# Start everything with Docker
docker-compose up -d

# Access dashboard
open http://localhost:8000
```

## ✅ Verify It's Working

```bash
# Health check
curl http://localhost:8000/health

# Should return: {"status": "healthy", "version": "1.0.0"}
```

## 🆘 Need Help?

- **Full Instructions**: See `RUN_INSTRUCTIONS.md`
- **Troubleshooting**: Check the logs in `logs/` directory
- **API Documentation**: See `docs/API.md`

## 🎯 What You'll See

- **Real-time Dashboard**: Live threat monitoring
- **Network Activity**: Packet capture and analysis
- **Threat Detection**: AI-powered threat identification
- **System Metrics**: CPU, memory, and network usage
- **Alerts**: Real-time security notifications

That's it! Your cybersecurity system is now running! 🛡️
