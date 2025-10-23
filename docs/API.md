# API Documentation

## Overview

The Cybersecurity System provides a RESTful API for monitoring, configuration, and data access.

## Base URL

```
http://localhost:8000
```

## Authentication

Currently, the API does not require authentication. In production, implement proper authentication mechanisms.

## Endpoints

### System Status

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1703123456.789,
  "version": "1.0.0"
}
```

#### GET /api/v1/status
Get system component status.

**Response:**
```json
{
  "network_monitor": true,
  "stream_processor": true,
  "alert_manager": true,
  "timestamp": 1703123456.789
}
```

### Performance Metrics

#### GET /api/v1/performance
Get system performance metrics.

**Response:**
```json
{
  "events_processed": 1250,
  "threats_detected": 15,
  "processing_time": 0.045,
  "last_update": 1703123456.789
}
```

### Threat Detection

#### GET /api/v1/threat-stats
Get aggregated threat statistics.

**Response:**
```json
{
  "timestamp": 1703123456.789,
  "threat_types": {
    "potential_threat": 5,
    "high_threat": 3,
    "suspicious": 7
  },
  "severity_counts": {
    "low": 2,
    "medium": 7,
    "high": 3,
    "critical": 3
  },
  "total_threats": 15
}
```

#### GET /api/v1/threats
Get recent threat events.

**Response:**
```json
[
  {
    "timestamp": 1703123456.789,
    "event_type": "network_packet",
    "severity": "high",
    "threat_result": {
      "is_threat": true,
      "threat_score": 0.85,
      "threat_type": "high_threat",
      "confidence": 0.92,
      "explanation": "High CPU usage detected. Unusual number of active connections"
    },
    "packet_data": {
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "src_port": 12345,
      "dst_port": 80,
      "protocol": "tcp",
      "packet_size": 1024
    }
  }
]
```

### Events and Monitoring

#### GET /api/v1/events
Get recent processed events.

**Response:**
```json
[
  {
    "timestamp": 1703123456.789,
    "event_type": "network_packet",
    "severity": "low",
    "threat_result": {
      "is_threat": false,
      "threat_score": 0.15,
      "threat_type": "normal",
      "confidence": 0.85
    },
    "packet_data": {
      "src_ip": "192.168.1.50",
      "dst_ip": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 53,
      "protocol": "udp",
      "packet_size": 512
    }
  }
]
```

#### GET /api/v1/alerts
Get recent alerts.

**Response:**
```json
[
  {
    "id": "alert_1703123456_12345",
    "timestamp": 1703123456.789,
    "severity": "high",
    "title": "Threat Detected: high_threat",
    "description": "High CPU usage detected. Unusual number of active connections",
    "channels": ["email", "log"],
    "sent": true
  }
]
```

### Network Data

#### GET /api/v1/network/packets
Get recent network packets.

**Response:**
```json
[
  {
    "timestamp": 1703123456.789,
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "src_port": 12345,
    "dst_port": 80,
    "protocol": "tcp",
    "packet_size": 1024,
    "flags": "PA"
  }
]
```

#### GET /api/v1/network/metrics
Get recent system metrics.

**Response:**
```json
[
  {
    "timestamp": 1703123456.789,
    "cpu_percent": 45.2,
    "memory_percent": 67.8,
    "disk_usage": 23.4,
    "network_io": {
      "bytes_sent": 1024000,
      "bytes_recv": 2048000,
      "packets_sent": 1500,
      "packets_recv": 2000
    },
    "active_connections": 25
  }
]
```

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid request parameters"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error"
}
```

### 503 Service Unavailable
```json
{
  "detail": "Service component not available"
}
```

## Rate Limiting

Currently, no rate limiting is implemented. In production, implement appropriate rate limiting.

## WebSocket Support

For real-time updates, WebSocket connections can be established:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Real-time update:', data);
};
```

## Data Formats

### Timestamps
All timestamps are Unix timestamps (seconds since epoch).

### IP Addresses
IP addresses are in standard dotted decimal notation (e.g., "192.168.1.100").

### Ports
Ports are integers in the range 0-65535.

### Threat Scores
Threat scores are floating-point numbers between 0.0 and 1.0, where:
- 0.0-0.3: Low threat
- 0.3-0.6: Medium threat
- 0.6-0.8: High threat
- 0.8-1.0: Critical threat

## Examples

### Python Client
```python
import requests

# Get system status
response = requests.get('http://localhost:8000/api/v1/status')
status = response.json()

# Get threat statistics
response = requests.get('http://localhost:8000/api/v1/threat-stats')
threat_stats = response.json()

# Get recent events
response = requests.get('http://localhost:8000/api/v1/events')
events = response.json()
```

### JavaScript Client
```javascript
// Get system status
fetch('http://localhost:8000/api/v1/status')
    .then(response => response.json())
    .then(data => console.log('Status:', data));

// Get threat statistics
fetch('http://localhost:8000/api/v1/threat-stats')
    .then(response => response.json())
    .then(data => console.log('Threat stats:', data));
```

### cURL Examples
```bash
# Health check
curl http://localhost:8000/health

# System status
curl http://localhost:8000/api/v1/status

# Threat statistics
curl http://localhost:8000/api/v1/threat-stats

# Recent events
curl http://localhost:8000/api/v1/events
```
