#!/usr/bin/env python3
"""
Simple runner script for the Cybersecurity System
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import redis
        import psutil
        import scapy
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please install dependencies with: pip install -r requirements.txt")
        return False

def check_redis():
    """Check if Redis is running"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis is running")
        return True
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        print("Please start Redis server: redis-server")
        return False

def create_directories():
    """Create necessary directories"""
    directories = ['logs', 'models', 'data']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✅ Directories created")

def main():
    """Main runner function"""
    print("🛡️  Starting Generative AI-Based Smart Cybersecurity System")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check Redis
    if not check_redis():
        print("⚠️  Redis not available, some features may not work")
    
    # Create directories
    create_directories()
    
    # Start the application
    print("\n🚀 Starting the application...")
    print("Dashboard will be available at: http://localhost:8000")
    print("Press Ctrl+C to stop the application")
    print("=" * 60)
    
    try:
        # Import and run the main application
        from main import app
        import uvicorn
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
            reload=True
        )
    except KeyboardInterrupt:
        print("\n\n🛑 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
