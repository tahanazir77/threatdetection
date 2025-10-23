#!/bin/bash

# Cybersecurity System Installation Script
# This script automates the installation process

set -e  # Exit on any error

echo "🛡️  Installing Generative AI-Based Smart Cybersecurity System"
echo "=============================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python is installed
check_python() {
    print_status "Checking Python installation..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_status "Python $PYTHON_VERSION found"
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version 2>&1 | cut -d' ' -f2)
        print_status "Python $PYTHON_VERSION found"
        PYTHON_CMD="python"
    else
        print_error "Python is not installed. Please install Python 3.8 or higher."
        exit 1
    fi
}

# Check if pip is installed
check_pip() {
    print_status "Checking pip installation..."
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        print_error "pip is not installed. Please install pip."
        exit 1
    fi
    print_status "pip found"
}

# Check if Redis is installed
check_redis() {
    print_status "Checking Redis installation..."
    if command -v redis-server &> /dev/null; then
        print_status "Redis found"
    else
        print_warning "Redis is not installed. Installing Redis..."
        install_redis
    fi
}

# Install Redis based on OS
install_redis() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y redis-server
        elif command -v yum &> /dev/null; then
            sudo yum install -y redis
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y redis
        else
            print_error "Cannot install Redis automatically. Please install Redis manually."
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install redis
        else
            print_error "Homebrew not found. Please install Redis manually or install Homebrew first."
            exit 1
        fi
    else
        print_error "Unsupported operating system. Please install Redis manually."
        exit 1
    fi
}

# Create virtual environment
create_venv() {
    print_status "Creating Python virtual environment..."
    if [ ! -d "venv" ]; then
        $PYTHON_CMD -m venv venv
        print_status "Virtual environment created"
    else
        print_status "Virtual environment already exists"
    fi
}

# Activate virtual environment
activate_venv() {
    print_status "Activating virtual environment..."
    source venv/bin/activate
    print_status "Virtual environment activated"
}

# Install Python dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    print_status "Dependencies installed successfully"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p logs models data
    print_status "Directories created"
}

# Copy environment file
setup_environment() {
    print_status "Setting up environment configuration..."
    if [ ! -f ".env" ]; then
        cp config/env_example.txt .env
        print_status "Environment file created. Please edit .env with your configuration."
    else
        print_status "Environment file already exists"
    fi
}

# Start Redis server
start_redis() {
    print_status "Starting Redis server..."
    if pgrep -x "redis-server" > /dev/null; then
        print_status "Redis server is already running"
    else
        redis-server --daemonize yes
        print_status "Redis server started"
    fi
}

# Test installation
test_installation() {
    print_status "Testing installation..."
    
    # Test Python imports
    $PYTHON_CMD -c "
import fastapi
import uvicorn
import redis
import psutil
import scapy
print('All required packages imported successfully')
" 2>/dev/null || {
        print_error "Some packages failed to import. Please check the installation."
        exit 1
    }
    
    # Test Redis connection
    redis-cli ping > /dev/null 2>&1 || {
        print_error "Cannot connect to Redis. Please check Redis installation."
        exit 1
    }
    
    print_status "Installation test passed"
}

# Main installation function
main() {
    echo "Starting installation process..."
    
    check_python
    check_pip
    check_redis
    create_venv
    activate_venv
    install_dependencies
    create_directories
    setup_environment
    start_redis
    test_installation
    
    echo ""
    echo "🎉 Installation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Edit .env file with your configuration"
    echo "2. Run: python run.py"
    echo "3. Open http://localhost:8000 in your browser"
    echo ""
    echo "For detailed instructions, see RUN_INSTRUCTIONS.md"
}

# Run main function
main "$@"
