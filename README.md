# 🛡️ Generative AI-Based Smart Cybersecurity System

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](docker/)

A comprehensive cybersecurity system that uses generative AI and machine learning techniques to detect and respond to threats in real-time. This system provides enterprise-grade threat detection with sub-second response times and a beautiful web dashboard for monitoring and management.

## 🌟 Key Features

- **Real-time Threat Detection**: AI-powered analysis with sub-second response
- **Multi-Model AI**: Isolation Forest, Random Forest, and Deep Learning models
- **Network Monitoring**: Packet capture and traffic analysis using Scapy
- **System Monitoring**: CPU, memory, and resource tracking
- **Web Dashboard**: Real-time visualization with interactive charts
- **Multi-channel Alerting**: Email, Slack, Webhook, and Log notifications
- **RESTful API**: Complete API for integration and automation
- **Docker Support**: Production-ready containerized deployment

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Architecture](#️-architecture)
- [API Documentation](#-api-documentation)
- [Docker Deployment](#-docker-deployment)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

### Option 1: Automated Installation
```bash
# Linux/macOS
./install.sh

# Windows
install.bat
```

### Option 2: Manual Installation
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start Redis
redis-server

# 3. Run the system
python run.py

# 4. Access dashboard
open http://localhost:8000
```

### Option 3: Docker
```bash
docker-compose up -d
open http://localhost:8000
```

## 📋 Prerequisites

Before installing the cybersecurity system, ensure you have:

- **Python 3.8+** (recommended: Python 3.9 or 3.10)
- **Redis Server** (version 6.0+)
- **4GB RAM** (8GB recommended for optimal performance)
- **Network monitoring privileges** (for packet capture)
- **Git** (for cloning the repository)

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 4GB | 8GB+ |
| CPU | 2 cores | 4+ cores |
| Storage | 10GB | 50GB+ |
| OS | Linux/macOS/Windows | Linux |

## 📦 Installation

### GitHub Setup

#### Prerequisites for GitHub
- **Git** installed on your system
- **GitHub account** (create one at [github.com](https://github.com))
- **SSH key** set up (recommended) or Personal Access Token

#### SSH Key Setup (Recommended)
1. **Generate SSH key** (if you don't have one):
   ```bash
   ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
   ```

2. **Add SSH key to GitHub**:
   - Copy your public key: `cat ~/.ssh/id_rsa.pub`
   - Go to GitHub → Settings → SSH and GPG keys → New SSH key
   - Paste your key and save

3. **Test SSH connection**:
   ```bash
   ssh -T git@github.com
   ```

#### Clone the Repository
```bash
# Using SSH (recommended)
git clone git@github.com:tahanazir77/threatdetection.git
cd threatdetection

# Or using HTTPS
git clone https://github.com/tahanazir77/threatdetection.git
cd threatdetection
```

### Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Or use a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Start Redis Server
```bash
# On Linux/macOS
redis-server

# On Windows (if installed via installer)
redis-server.exe

# Or using Docker
docker run -d -p 6379:6379 redis:latest
```

## ✨ Features
- **Real-time Threat Detection**: AI-powered analysis with sub-second response
- **Network Monitoring**: Packet capture and traffic analysis
- **System Monitoring**: CPU, memory, and resource tracking
- **Multi-Model AI**: Isolation Forest, Random Forest, and Deep Learning
- **Web Dashboard**: Real-time visualization and control
- **Multi-channel Alerting**: Email, Slack, Webhook, and Log notifications
- **RESTful API**: Complete API for integration and automation

## 🏗️ Architecture
- **Data Collection Layer**: Network monitoring, system logs, and security events
- **AI Processing Layer**: Machine learning models for threat detection
- **Real-time Processing**: Stream processing for immediate threat response
- **Dashboard Layer**: Web interface for monitoring and management
- **Alerting System**: Automated notifications and response actions

## 🛠️ Technology Stack
- **Backend**: Python 3.8+, FastAPI, Redis, PostgreSQL
- **AI/ML**: TensorFlow, PyTorch, Scikit-learn, Scapy
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js
- **Infrastructure**: Docker, Docker Compose
- **Monitoring**: Real-time metrics and logging

## 📚 Documentation
- **[Quick Start Guide](QUICK_START.md)** - Get running in 5 minutes
- **[Detailed Instructions](RUN_INSTRUCTIONS.md)** - Complete setup guide
- **[API Documentation](docs/API.md)** - RESTful API reference
- **[Setup Guide](docs/SETUP.md)** - Installation and configuration
- **[Project Summary](PROJECT_SUMMARY.md)** - Comprehensive overview

## ⚙️ Configuration

### Environment Variables
Copy the example environment file and configure your settings:

```bash
cp .env.example .env
```

Edit `.env` file to configure:
- **Database connections**: PostgreSQL connection string
- **Redis settings**: Redis server URL and configuration
- **AI model parameters**: Threat detection thresholds and model paths
- **Alerting channels**: Email, Slack, and webhook configurations
- **Network monitoring**: Interface names and packet capture settings
- **Security settings**: Secret keys and authentication tokens

### Key Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `THREAT_THRESHOLD` | Minimum score for threat detection | 0.7 |
| `ANOMALY_THRESHOLD` | Threshold for anomaly detection | 0.8 |
| `MONITOR_INTERFACES` | Network interfaces to monitor | eth0,wlan0 |
| `ALERT_COOLDOWN` | Alert cooldown period (seconds) | 300 |
| `LOG_LEVEL` | Logging verbosity | INFO |

## 🚀 Usage

### Start the System
```bash
# Run the main application
python run.py

# Or run specific components
python main.py
```

### Access the Dashboard
- **Web Dashboard**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 📊 Monitoring
- **Dashboard**: http://localhost:8000
- **Health Check**: http://localhost:8000/health
- **API Status**: http://localhost:8000/api/v1/status
- **Performance**: http://localhost:8000/api/v1/performance

## 🧪 Testing

### Local Testing
```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_specific.py

# Run with verbose output
pytest -v
```

### GitHub Actions CI/CD
This repository includes automated CI/CD pipelines:

- **Automated Testing**: Runs on Python 3.8, 3.9, 3.10, 3.11
- **Code Quality**: Linting with flake8, type checking with mypy
- **Security Scanning**: Bandit security analysis
- **Coverage Reports**: Code coverage tracking
- **Docker Build**: Automated Docker image building
- **Dependency Scanning**: Security vulnerability checks

View the [Actions tab](https://github.com/tahanazir77/threatdetection/actions) to see CI/CD status.

## 🐳 Docker Support
```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 📁 Project Structure
```
├── src/                    # Source code
│   ├── data_collection/   # Network and system monitoring
│   ├── ai_models/         # ML models for threat detection
│   ├── real_time/         # Stream processing
│   ├── dashboard/         # Web dashboard
│   ├── alerting/          # Notification system
│   └── utils/             # Utility functions
├── config/                # Configuration files
├── docs/                  # Documentation
├── tests/                 # Test files
├── docker/                # Docker configurations
├── install.sh             # Linux/macOS installer
├── install.bat            # Windows installer
└── run.py                 # Application runner
```

## 🆘 Support
- **Issues**: Check logs in `logs/` directory
- **Documentation**: See `docs/` directory
- **Troubleshooting**: See `RUN_INSTRUCTIONS.md`
- **API Reference**: See `docs/API.md`

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Fork and Contribute
1. **Fork the repository**:
   - Go to [https://github.com/tahanazir77/threatdetection](https://github.com/tahanazir77/threatdetection)
   - Click the "Fork" button in the top right

2. **Clone your fork**:
   ```bash
   git clone git@github.com:YOUR_USERNAME/threatdetection.git
   cd threatdetection
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream git@github.com:tahanazir77/threatdetection.git
   ```

4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

5. **Make your changes and commit**:
   ```bash
   git add .
   git commit -m "Add your feature description"
   ```

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**:
   - Go to your fork on GitHub
   - Click "Compare & pull request"
   - Fill out the PR template

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/tahanazir77/threatdetection.git
cd threatdetection

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
black src/
flake8 src/
```

### Reporting Issues
- Use the [GitHub Issues](https://github.com/tahanazir77/threatdetection/issues) page
- Include system information and error logs
- Provide steps to reproduce the issue

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) for the web framework
- [Scapy](https://scapy.net/) for network packet capture
- [TensorFlow](https://tensorflow.org/) and [PyTorch](https://pytorch.org/) for AI models
- [Redis](https://redis.io/) for real-time data storage

## 📞 Support

- **Documentation**: Check the `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/tahanazir77/threatdetection/issues)
- **Discussions**: [GitHub Discussions](https://github.com/tahanazir77/threatdetection/discussions)

---

⭐ **Star this repository** if you find it helpful!
