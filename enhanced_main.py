#!/usr/bin/env python3
"""
Enhanced Cybersecurity System with Website Threat Detection
"""

import asyncio
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
import logging
from loguru import logger
import json
import time
import random
from typing import Dict, List
import redis

# Configure logging
logging.basicConfig(level=logging.INFO)
logger.add("logs/cybersecurity_system.log", rotation="1 day", retention="30 days")

# Global instances
redis_client = None
threat_stats = {
    'total_events': 0,
    'threats_detected': 0,
    'threat_types': {},
    'severity_counts': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global redis_client
    
    logger.info("Starting Enhanced Cybersecurity System...")
    
    # Initialize Redis connection
    try:
        redis_client = redis.Redis(host='localhost', port=6379, db=0)
        redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}")
        redis_client = None
    
    # Start background tasks
    asyncio.create_task(generate_website_data())
    
    logger.info("Enhanced Cybersecurity System started successfully")
    
    yield
    
    # Cleanup
    logger.info("Shutting down Enhanced Cybersecurity System...")
    if redis_client:
        redis_client.close()
    logger.info("Enhanced Cybersecurity System stopped")

# Create FastAPI app
app = FastAPI(
    title="Enhanced Cybersecurity System",
    description="Real-time website threat detection and monitoring",
    version="2.0.0",
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

async def generate_website_data():
    """Generate simulated website access data with threat analysis"""
    global threat_stats
    
    # Sample websites with threat classifications
    websites = [
        {'domain': 'google.com', 'name': 'Google Search', 'threat_level': 'normal', 'reason': 'Legitimate search engine'},
        {'domain': 'facebook.com', 'name': 'Facebook', 'threat_level': 'normal', 'reason': 'Social media platform'},
        {'domain': 'github.com', 'name': 'GitHub', 'threat_level': 'normal', 'reason': 'Code repository platform'},
        {'domain': 'stackoverflow.com', 'name': 'Stack Overflow', 'threat_level': 'normal', 'reason': 'Developer Q&A site'},
        {'domain': 'malware-site.com', 'name': 'Suspicious Site', 'threat_level': 'high', 'reason': 'Known malware distribution'},
        {'domain': 'phishing-bank.com', 'name': 'Fake Bank Site', 'threat_level': 'critical', 'reason': 'Phishing attempt - fake banking'},
        {'domain': 'crypto-miner.net', 'name': 'Crypto Mining Site', 'threat_level': 'high', 'reason': 'Cryptocurrency mining malware'},
        {'domain': 'torrent-tracker.org', 'name': 'Torrent Tracker', 'threat_level': 'medium', 'reason': 'P2P file sharing - potential malware'},
        {'domain': 'adult-content.net', 'name': 'Adult Content Site', 'threat_level': 'medium', 'reason': 'Adult content - potential security risk'},
        {'domain': 'dark-web-market.onion', 'name': 'Dark Web Market', 'threat_level': 'critical', 'reason': 'Dark web marketplace - illegal activities'},
        {'domain': 'fake-antivirus.com', 'name': 'Fake Antivirus', 'threat_level': 'high', 'reason': 'Scareware - fake security software'},
        {'domain': 'credit-card-stealer.org', 'name': 'Credit Card Stealer', 'threat_level': 'critical', 'reason': 'Credit card information theft'},
        {'domain': 'ransomware-download.net', 'name': 'Ransomware Site', 'threat_level': 'critical', 'reason': 'Ransomware distribution'},
        {'domain': 'botnet-command.com', 'name': 'Botnet Command', 'threat_level': 'critical', 'reason': 'Botnet command and control server'},
        {'domain': 'data-exfiltration.org', 'name': 'Data Exfiltration', 'threat_level': 'high', 'reason': 'Data theft and exfiltration'},
    ]
    
    while True:
        try:
            # Select a random website
            website = random.choice(websites)
            
            # Generate threat score based on website threat level
            threat_scores = {
                'normal': random.uniform(0, 0.3),
                'medium': random.uniform(0.4, 0.6),
                'high': random.uniform(0.7, 0.85),
                'critical': random.uniform(0.86, 1.0)
            }
            
            threat_score = threat_scores[website['threat_level']]
            
            # Generate website access event
            event = {
                'timestamp': time.time(),
                'event_type': 'website_access',
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443]),
                'protocol': 'HTTP' if random.choice([80, 443]) == 80 else 'HTTPS',
                'packet_size': random.randint(64, 1500),
                'threat_score': threat_score,
                'threat_type': website['threat_level'],
                'severity': website['threat_level'],
                'website_domain': website['domain'],
                'website_name': website['name'],
                'threat_reason': website['reason'],
                'user_agent': random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                ]),
                'http_method': random.choice(['GET', 'POST', 'PUT']),
                'response_code': random.choice([200, 301, 302, 404, 500])
            }
            
            # Determine if it's a threat
            if event['threat_score'] > 0.7:
                event['is_threat'] = True
                threat_stats['threats_detected'] += 1
                threat_stats['threat_types'][event['threat_type']] = threat_stats['threat_types'].get(event['threat_type'], 0) + 1
                threat_stats['severity_counts'][event['severity']] += 1
            else:
                event['is_threat'] = False
            
            threat_stats['total_events'] += 1
            
            # Store in Redis if available
            if redis_client:
                try:
                    redis_client.lpush('recent_events', json.dumps(event))
                    redis_client.ltrim('recent_events', 0, 999)  # Keep last 1000
                    
                    if event['is_threat']:
                        redis_client.lpush('threat_events', json.dumps(event))
                        redis_client.ltrim('threat_events', 0, 499)  # Keep last 500
                except Exception as e:
                    logger.error(f"Error storing in Redis: {e}")
            
            # Wait before next event
            await asyncio.sleep(random.uniform(0.5, 2.0))
            
        except Exception as e:
            logger.error(f"Error generating website data: {e}")
            await asyncio.sleep(5)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Enhanced Cybersecurity System",
        "status": "running",
        "version": "2.0.0",
        "mode": "website_threat_detection"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "redis_connected": redis_client is not None,
        "components": {
            "website_monitor": "running",
            "threat_detector": "running",
            "dashboard": "running"
        }
    }

@app.get("/api/v1/status")
async def get_status():
    """Get system status"""
    return {
        "status": "running",
        "uptime": "active",
        "components": {
            "website_monitor": "active",
            "threat_detector": "active",
            "dashboard": "active"
        },
        "statistics": threat_stats
    }

@app.get("/api/v1/events")
async def get_recent_events(limit: int = 50):
    """Get recent website access events"""
    try:
        if redis_client:
            events = redis_client.lrange('recent_events', 0, limit - 1)
            return [json.loads(event) for event in events]
        else:
            # Return simulated data if Redis not available
            websites = [
                {'domain': 'google.com', 'name': 'Google Search', 'threat_level': 'normal', 'reason': 'Legitimate search engine'},
                {'domain': 'malware-site.com', 'name': 'Suspicious Site', 'threat_level': 'high', 'reason': 'Known malware distribution'},
                {'domain': 'phishing-bank.com', 'name': 'Fake Bank Site', 'threat_level': 'critical', 'reason': 'Phishing attempt - fake banking'},
                {'domain': 'github.com', 'name': 'GitHub', 'threat_level': 'normal', 'reason': 'Code repository platform'},
                {'domain': 'ransomware-download.net', 'name': 'Ransomware Site', 'threat_level': 'critical', 'reason': 'Ransomware distribution'},
            ]
            
            return [{
                'timestamp': time.time() - i,
                'event_type': 'website_access',
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'threat_score': random.uniform(0, 1),
                'is_threat': random.choice([True, False]),
                'website_domain': random.choice(websites)['domain'],
                'website_name': random.choice(websites)['name'],
                'threat_reason': random.choice(websites)['reason'],
                'protocol': random.choice(['HTTP', 'HTTPS']),
                'http_method': random.choice(['GET', 'POST'])
            } for i in range(limit)]
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return []

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Enhanced dashboard with website threat analysis"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Enhanced Cybersecurity Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
            .stat-label { color: #7f8c8d; margin-top: 5px; }
            .threat { color: #e74c3c; }
            .normal { color: #27ae60; }
            .events { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .event-item { padding: 15px; margin: 10px 0; border-radius: 5px; }
            .refresh-btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
            .refresh-btn:hover { background: #2980b9; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Enhanced Cybersecurity Dashboard</h1>
                <p>Real-time website threat detection and monitoring</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value" id="total-events">-</div>
                    <div class="stat-label">Total Website Visits</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value threat" id="threats-detected">-</div>
                    <div class="stat-label">Threats Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="threat-rate">-</div>
                    <div class="stat-label">Threat Rate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value normal" id="system-status">-</div>
                    <div class="stat-label">System Status</div>
                </div>
            </div>
            
            <div class="events">
                <h2>Recent Website Access Events</h2>
                <button class="refresh-btn" onclick="loadData()">Refresh</button>
                <div id="events-list">Loading...</div>
            </div>
            
            <div class="threat-details" style="background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-top: 20px;">
                <h2>Threat Analysis</h2>
                <div id="threat-analysis">Loading threat analysis...</div>
            </div>
        </div>
        
        <script>
            async function loadData() {
                try {
                    // Load status
                    const statusResponse = await fetch('/api/v1/status');
                    const status = await statusResponse.json();
                    
                    document.getElementById('total-events').textContent = status.statistics.total_events;
                    document.getElementById('threats-detected').textContent = status.statistics.threats_detected;
                    document.getElementById('threat-rate').textContent = 
                        status.statistics.total_events > 0 ? 
                        (status.statistics.threats_detected / status.statistics.total_events * 100).toFixed(1) + '%' : '0%';
                    document.getElementById('system-status').textContent = 'Active';
                    
                    // Load recent events
                    const eventsResponse = await fetch('/api/v1/events?limit=10');
                    const events = await eventsResponse.json();
                    
                    const eventsList = document.getElementById('events-list');
                    eventsList.innerHTML = events.map(event => `
                        <div class="event-item" style="border-left: 4px solid ${event.is_threat ? '#e74c3c' : '#27ae60'}; background: ${event.is_threat ? '#ffeaea' : '#f0fff0'};">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <strong>${new Date(event.timestamp * 1000).toLocaleTimeString()}</strong>
                                    <div style="font-size: 1.2em; font-weight: bold; color: ${event.is_threat ? '#e74c3c' : '#27ae60'};">
                                        ${event.website_name || 'Unknown Site'}
                                    </div>
                                    <div style="color: #666; font-size: 0.9em;">
                                        ${event.website_domain || event.src_ip + ' → ' + event.dst_ip}
                                    </div>
                                    ${event.threat_reason ? `<div style="color: #e67e22; font-size: 0.9em; margin-top: 5px;">
                                        <strong>Threat Reason:</strong> ${event.threat_reason}
                                    </div>` : ''}
                                </div>
                                <div style="text-align: right;">
                                    <div class="${event.is_threat ? 'threat' : 'normal'}" style="font-weight: bold; font-size: 1.1em;">
                                        ${event.is_threat ? '🚨 THREAT' : '✅ SAFE'}
                                    </div>
                                    <div style="font-size: 0.9em; color: #666;">
                                        Score: ${(event.threat_score * 100).toFixed(1)}%
                                    </div>
                                    <div style="font-size: 0.9em; color: #666;">
                                        ${event.protocol} • ${event.http_method || 'N/A'}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `).join('');
                    
                    // Load threat analysis
                    const threatEvents = events.filter(event => event.is_threat);
                    const threatAnalysis = document.getElementById('threat-analysis');
                    
                    if (threatEvents.length > 0) {
                        threatAnalysis.innerHTML = `
                            <div style="background: #fff5f5; border: 1px solid #fecaca; border-radius: 5px; padding: 15px;">
                                <h3 style="color: #dc2626; margin-top: 0;">🚨 Active Threats Detected</h3>
                                ${threatEvents.map(event => `
                                    <div style="margin: 10px 0; padding: 10px; background: white; border-radius: 3px; border-left: 4px solid #dc2626;">
                                        <strong>${event.website_name}</strong> (${event.website_domain})
                                        <div style="color: #dc2626; font-size: 0.9em; margin-top: 5px;">
                                            <strong>Threat Level:</strong> ${event.threat_type.toUpperCase()}
                                        </div>
                                        <div style="color: #7c2d12; font-size: 0.9em;">
                                            <strong>Reason:</strong> ${event.threat_reason}
                                        </div>
                                        <div style="color: #666; font-size: 0.8em; margin-top: 5px;">
                                            Accessed at ${new Date(event.timestamp * 1000).toLocaleString()}
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        `;
                    } else {
                        threatAnalysis.innerHTML = `
                            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 5px; padding: 15px; text-align: center;">
                                <h3 style="color: #16a34a; margin-top: 0;">✅ No Active Threats</h3>
                                <p style="color: #166534;">All recent website accesses appear to be safe.</p>
                            </div>
                        `;
                    }
                    
                } catch (error) {
                    console.error('Error loading data:', error);
                    document.getElementById('events-list').innerHTML = 'Error loading data';
                }
            }
            
            // Load data on page load and refresh every 5 seconds
            loadData();
            setInterval(loadData, 5000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    # Create logs directory
    import os
    os.makedirs("logs", exist_ok=True)
    
    # Run the application
    uvicorn.run(
        "enhanced_main:app",
        host="0.0.0.0",
        port=8003,
        reload=True,
        log_level="info"
    )
