#!/usr/bin/env python3
"""
Main entry point for the Generative AI-Based Smart Cybersecurity System
"""

import asyncio
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from loguru import logger

from src.dashboard.routes import router as dashboard_router
from src.data_collection.network_monitor import NetworkMonitor
from src.real_time.stream_processor import StreamProcessor
from src.alerting.alert_manager import AlertManager
from config.settings import Settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger.add("logs/cybersecurity_system.log", rotation="1 day", retention="30 days")

# Global instances
network_monitor = None
stream_processor = None
alert_manager = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global network_monitor, stream_processor, alert_manager
    
    logger.info("Starting Cybersecurity System...")
    
    # Initialize components
    settings = Settings()
    
    # Initialize network monitor
    network_monitor = NetworkMonitor(settings)
    await network_monitor.start()
    
    # Initialize stream processor
    stream_processor = StreamProcessor(settings)
    await stream_processor.start()
    
    # Initialize alert manager
    alert_manager = AlertManager(settings)
    await alert_manager.start()
    
    logger.info("Cybersecurity System started successfully")
    
    yield
    
    # Cleanup
    logger.info("Shutting down Cybersecurity System...")
    if network_monitor:
        await network_monitor.stop()
    if stream_processor:
        await stream_processor.stop()
    if alert_manager:
        await alert_manager.stop()
    logger.info("Cybersecurity System stopped")

# Create FastAPI app
app = FastAPI(
    title="Generative AI-Based Smart Cybersecurity System",
    description="Real-time threat detection and response system",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(dashboard_router, prefix="/api/v1")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Generative AI-Based Smart Cybersecurity System",
        "status": "running",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "components": {
            "network_monitor": network_monitor.is_running() if network_monitor else False,
            "stream_processor": stream_processor.is_running() if stream_processor else False,
            "alert_manager": alert_manager.is_running() if alert_manager else False
        }
    }

if __name__ == "__main__":
    # Create logs directory
    import os
    os.makedirs("logs", exist_ok=True)
    
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
