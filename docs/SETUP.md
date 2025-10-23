# Setup Guide

## Prerequisites

- Python 3.8 or higher
- Docker and Docker Compose (optional)
- Redis server
- PostgreSQL database (optional)
- Network monitoring privileges (for packet capture)

## Installation

### Option 1: Local Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd tahaproject
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp config/env_example.txt .env
   # Edit .env with your configuration
   ```

5. **Start Redis server**
   ```bash
   redis-server
   ```

6. **Run the application**
   ```bash
   python main.py
   ```

### Option 2: Docker Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd tahaproject
   ```

2. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Access the dashboard**
   Open http://localhost:8000 in your browser

## Configuration

### Environment Variables

Key configuration options in `.env`:

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: Secret key for security
- `THREAT_THRESHOLD`: Threat detection threshold (0.0-1.0)
- `ALERT_EMAIL_ENABLED`: Enable email alerts
- `ALERT_SLACK_ENABLED`: Enable Slack alerts

### Network Monitoring

For network packet capture, the system needs:

- Root privileges (for raw socket access)
- Network interface access
- Firewall rules to allow monitoring

### AI Models

The system includes pre-trained models for threat detection. You can:

- Train custom models with your data
- Update models periodically
- Use different model architectures

## Usage

### Starting the System

1. **Start all components**
   ```bash
   python main.py
   ```

2. **Check system status**
   ```bash
   curl http://localhost:8000/health
   ```

3. **Access dashboard**
   Open http://localhost:8000

### Monitoring

The dashboard provides:

- Real-time threat detection
- System performance metrics
- Network activity visualization
- Alert management
- Historical data analysis

### API Endpoints

- `GET /` - Main dashboard
- `GET /health` - Health check
- `GET /api/v1/status` - System status
- `GET /api/v1/performance` - Performance metrics
- `GET /api/v1/threat-stats` - Threat statistics
- `GET /api/v1/alerts` - Recent alerts
- `GET /api/v1/events` - Recent events

## Troubleshooting

### Common Issues

1. **Permission denied for network monitoring**
   - Run with sudo privileges
   - Check network interface permissions

2. **Redis connection failed**
   - Ensure Redis server is running
   - Check Redis URL configuration

3. **Model loading errors**
   - Check model file paths
   - Ensure model files exist

4. **High CPU usage**
   - Adjust packet capture timeout
   - Reduce monitoring frequency
   - Optimize AI model parameters

### Logs

Check logs in the `logs/` directory:

- `cybersecurity_system.log` - Main application logs
- Error logs for specific components

### Performance Tuning

- Adjust `PACKET_CAPTURE_TIMEOUT` for network monitoring
- Modify `MAX_CONCURRENT_ANALYSES` for AI processing
- Configure Redis memory limits
- Optimize database queries

## Security Considerations

- Change default secret keys
- Use secure database connections
- Implement proper authentication
- Regular security updates
- Monitor system access logs

## Support

For issues and questions:

1. Check the logs for error messages
2. Review configuration settings
3. Consult the API documentation
4. Contact the development team
