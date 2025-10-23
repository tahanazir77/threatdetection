@echo off
REM Cybersecurity System Installation Script for Windows
REM This script automates the installation process on Windows

echo 🛡️  Installing Generative AI-Based Smart Cybersecurity System
echo ==============================================================

REM Check if Python is installed
echo [INFO] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed. Please install Python 3.8 or higher.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [INFO] Python found

REM Check if pip is installed
echo [INFO] Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is not installed. Please install pip.
    pause
    exit /b 1
)
echo [INFO] pip found

REM Create virtual environment
echo [INFO] Creating Python virtual environment...
if not exist "venv" (
    python -m venv venv
    echo [INFO] Virtual environment created
) else (
    echo [INFO] Virtual environment already exists
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat
echo [INFO] Virtual environment activated

REM Install Python dependencies
echo [INFO] Installing Python dependencies...
pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Please check the requirements.txt file.
    pause
    exit /b 1
)
echo [INFO] Dependencies installed successfully

REM Create necessary directories
echo [INFO] Creating necessary directories...
if not exist "logs" mkdir logs
if not exist "models" mkdir models
if not exist "data" mkdir data
echo [INFO] Directories created

REM Copy environment file
echo [INFO] Setting up environment configuration...
if not exist ".env" (
    copy config\env_example.txt .env
    echo [INFO] Environment file created. Please edit .env with your configuration.
) else (
    echo [INFO] Environment file already exists
)

REM Check Redis installation
echo [INFO] Checking Redis installation...
redis-server --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Redis is not installed.
    echo Please install Redis from: https://github.com/microsoftarchive/redis/releases
    echo Or use Docker: docker run -d -p 6379:6379 redis:alpine
    echo.
    echo You can continue without Redis, but some features may not work.
    echo.
) else (
    echo [INFO] Redis found
)

REM Test installation
echo [INFO] Testing installation...
python -c "import fastapi, uvicorn, redis, psutil, scapy; print('All required packages imported successfully')" 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Some packages failed to import. Please check the installation.
    pause
    exit /b 1
)
echo [INFO] Installation test passed

echo.
echo 🎉 Installation completed successfully!
echo.
echo Next steps:
echo 1. Edit .env file with your configuration
echo 2. Start Redis server (if installed)
echo 3. Run: python run.py
echo 4. Open http://localhost:8000 in your browser
echo.
echo For detailed instructions, see RUN_INSTRUCTIONS.md
echo.
pause
