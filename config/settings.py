"""
Configuration settings for the Cybersecurity System
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Application settings
    app_name: str = "Generative AI-Based Smart Cybersecurity System"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Database settings
    database_url: str = "postgresql://user:password@localhost:5432/cybersecurity_db"
    
    # Redis settings
    redis_url: str = "redis://localhost:6379/0"
    
    # AI Model settings
    model_path: str = "models/"
    model_update_interval: int = 3600  # seconds
    
    # Network monitoring settings
    monitor_interfaces: List[str] = ["eth0", "wlan0"]
    packet_capture_timeout: int = 30
    max_packet_size: int = 65536
    
    # Threat detection settings
    threat_threshold: float = 0.7
    anomaly_threshold: float = 0.8
    max_concurrent_analyses: int = 10
    
    # Alerting settings
    alert_email_enabled: bool = True
    alert_slack_enabled: bool = False
    alert_webhook_url: Optional[str] = None
    alert_cooldown: int = 300  # seconds
    
    # Logging settings
    log_level: str = "INFO"
    log_file: str = "logs/cybersecurity_system.log"
    log_rotation: str = "1 day"
    log_retention: str = "30 days"
    
    # Security settings
    secret_key: str = "your-secret-key-here"
    access_token_expire_minutes: int = 30
    
    # Dashboard settings
    dashboard_refresh_interval: int = 5  # seconds
    max_dashboard_history: int = 1000
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()
