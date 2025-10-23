#!/usr/bin/env python3
"""
Clean Real Traffic Capture - ONLY Real Network Packets, No Simulation
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
import redis
import socket
import threading
from scapy.all import sniff, IP, TCP, UDP, Raw

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

# Real traffic capture
real_traffic_enabled = False
captured_packets = []
packet_lock = threading.Lock()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global redis_client, real_traffic_enabled
    
    logger.info("Starting Clean Real Traffic Cybersecurity System...")
    
    # Initialize Redis connection
    try:
        redis_client = redis.Redis(host='localhost', port=6379, db=0)
        redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}")
        redis_client = None
    
    # Try to enable real traffic capture
    try:
        real_traffic_enabled = await enable_real_traffic_capture()
        if real_traffic_enabled:
            logger.info("✅ Real traffic capture enabled successfully!")
        else:
            logger.warning("❌ Real traffic capture failed")
    except Exception as e:
        logger.error(f"Error enabling real traffic capture: {e}")
        real_traffic_enabled = False
    
    # Start background tasks
    if real_traffic_enabled:
        asyncio.create_task(process_real_traffic())
    else:
        logger.error("Real traffic capture failed - system will not generate any data")
    
    logger.info("Clean Real Traffic Cybersecurity System started successfully")
    
    yield
    
    # Cleanup
    logger.info("Shutting down Clean Real Traffic Cybersecurity System...")
    if redis_client:
        redis_client.close()
    logger.info("Clean Real Traffic Cybersecurity System stopped")

async def enable_real_traffic_capture():
    """Try to enable real traffic capture"""
    try:
        logger.info("Attempting to enable real traffic capture...")
        
        # Start packet capture in a separate thread
        def start_packet_capture():
            try:
                logger.info("Starting packet capture thread...")
                sniff(
                    prn=process_packet,
                    store=0,
                    timeout=1
                )
            except Exception as e:
                logger.error(f"Packet capture error: {e}")
        
        # Start capture thread
        capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
        capture_thread.start()
        
        # Give it a moment to start
        await asyncio.sleep(2)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to enable real traffic capture: {e}")
        return False

def process_packet(packet):
    """Process captured network packet"""
    global captured_packets
    
    try:
        if IP in packet:
            packet_info = {
                'timestamp': time.time(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'packet_size': len(packet),
                'captured': True
            }
            
            # Extract port information for TCP/UDP
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['protocol_name'] = 'TCP'
            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['protocol_name'] = 'UDP'
            else:
                packet_info['protocol_name'] = 'ICMP'
            
            # Try to extract HTTP information
            if Raw in packet:
                try:
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'HTTP' in raw_data or 'GET' in raw_data or 'POST' in raw_data:
                        packet_info['http_data'] = raw_data[:200]  # First 200 chars
                except:
                    pass
            
            # Add to captured packets
            with packet_lock:
                captured_packets.append(packet_info)
                if len(captured_packets) > 1000:  # Keep last 1000 packets
                    captured_packets.pop(0)
                    
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

async def process_real_traffic():
    """Process real captured traffic"""
    global threat_stats
    
    while True:
        try:
            with packet_lock:
                if captured_packets:
                    # Process the most recent packets
                    recent_packets = captured_packets[-2:]  # Last 2 packets
                    captured_packets.clear()  # Clear processed packets
                else:
                    recent_packets = []
            
            for packet in recent_packets:
                # Enhance packet with website information
                enhanced_packet = await enhance_packet_with_website_info(packet)
                
                # Perform threat analysis
                threat_result = analyze_packet_threat(enhanced_packet)
                
                # Create event
                event = {
                    'timestamp': enhanced_packet['timestamp'],
                    'event_type': 'real_network_traffic',
                    'src_ip': enhanced_packet['src_ip'],
                    'dst_ip': enhanced_packet['dst_ip'],
                    'src_port': enhanced_packet.get('src_port'),
                    'dst_port': enhanced_packet.get('dst_port'),
                    'protocol': enhanced_packet.get('protocol_name', 'Unknown'),
                    'packet_size': enhanced_packet['packet_size'],
                    'website_domain': enhanced_packet.get('website_domain'),
                    'website_name': enhanced_packet.get('website_name'),
                    'threat_score': threat_result['threat_score'],
                    'threat_type': threat_result['threat_type'],
                    'threat_reason': threat_result['threat_reason'],
                    'is_threat': threat_result['is_threat'],
                    'captured': True
                }
                
                # Update statistics
                threat_stats['total_events'] += 1
                if event['is_threat']:
                    threat_stats['threats_detected'] += 1
                    threat_stats['threat_types'][event['threat_type']] = threat_stats['threat_types'].get(event['threat_type'], 0) + 1
                    threat_stats['severity_counts'][event['threat_type']] += 1
                
                # Store in Redis
                if redis_client:
                    try:
                        redis_client.lpush('recent_events', json.dumps(event))
                        redis_client.ltrim('recent_events', 0, 999)
                        
                        if event['is_threat']:
                            redis_client.lpush('threat_events', json.dumps(event))
                            redis_client.ltrim('threat_events', 0, 499)
                    except Exception as e:
                        logger.error(f"Error storing in Redis: {e}")
                
                logger.info(f"🟢 REAL PACKET: {event['src_ip']} -> {event['dst_ip']} ({event.get('website_domain', 'Unknown')})")
            
            await asyncio.sleep(2)  # Process every 2 seconds
            
        except Exception as e:
            logger.error(f"Error processing real traffic: {e}")
            await asyncio.sleep(5)

async def enhance_packet_with_website_info(packet):
    """Enhance packet with website information using DNS lookup"""
    enhanced = packet.copy()
    
    try:
        # Try to resolve destination IP to domain name
        if 'dst_ip' in packet:
            try:
                # Reverse DNS lookup
                hostname = socket.gethostbyaddr(packet['dst_ip'])[0]
                enhanced['website_domain'] = hostname
                enhanced['website_name'] = hostname.split('.')[0].title()
            except:
                # If reverse DNS fails, try to identify common services by port
                dst_port = packet.get('dst_port')
                if dst_port == 80:
                    enhanced['website_domain'] = f"http://{packet['dst_ip']}"
                    enhanced['website_name'] = "HTTP Service"
                elif dst_port == 443:
                    enhanced['website_domain'] = f"https://{packet['dst_ip']}"
                    enhanced['website_name'] = "HTTPS Service"
                elif dst_port == 22:
                    enhanced['website_domain'] = f"ssh://{packet['dst_ip']}"
                    enhanced['website_name'] = "SSH Service"
                elif dst_port == 53:
                    enhanced['website_domain'] = f"dns://{packet['dst_ip']}"
                    enhanced['website_name'] = "DNS Service"
                else:
                    enhanced['website_domain'] = packet['dst_ip']
                    enhanced['website_name'] = "Network Service"
    except Exception as e:
        logger.error(f"Error enhancing packet: {e}")
        enhanced['website_domain'] = packet.get('dst_ip', 'Unknown')
        enhanced['website_name'] = "Unknown"
    
    return enhanced

def analyze_packet_threat(packet):
    """Analyze packet for threats"""
    threat_score = 0.0
    threat_type = "normal"
    threat_reason = "Normal network traffic"
    
    try:
        # Check for suspicious ports
        dst_port = packet.get('dst_port')
        if dst_port:
            # Common threat ports
            if dst_port in [4444, 5555, 6666, 7777, 8888]:  # Common backdoor ports
                threat_score += 0.8
                threat_type = "high"
                threat_reason = f"Suspicious port {dst_port} - possible backdoor"
            elif dst_port in [21, 23, 135, 139, 445]:  # Potentially risky services
                threat_score += 0.4
                threat_type = "medium"
                threat_reason = f"Potentially risky service on port {dst_port}"
        
        # Check for large packet sizes (possible data exfiltration)
        if packet.get('packet_size', 0) > 1500:
            threat_score += 0.3
            if threat_type == "normal":
                threat_type = "medium"
            threat_reason += " - Large packet size detected"
        
        # Check for HTTP data
        if 'http_data' in packet:
            http_data = packet['http_data'].lower()
            if any(keyword in http_data for keyword in ['malware', 'virus', 'hack', 'exploit']):
                threat_score += 0.9
                threat_type = "critical"
                threat_reason = "Suspicious HTTP content detected"
            elif any(keyword in http_data for keyword in ['admin', 'login', 'password']):
                threat_score += 0.5
                if threat_type == "normal":
                    threat_type = "medium"
                threat_reason += " - Sensitive data in HTTP"
        
    except Exception as e:
        logger.error(f"Error analyzing packet threat: {e}")
    
    return {
        'threat_score': min(threat_score, 1.0),
        'threat_type': threat_type,
        'threat_reason': threat_reason,
        'is_threat': threat_score > 0.7
    }

# Create FastAPI app
app = FastAPI(
    title="Clean Real Traffic Cybersecurity System",
    description="Real-time network traffic monitoring - ONLY real packets",
    version="5.0.0",
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

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Clean Real Traffic Cybersecurity System",
        "status": "running",
        "version": "5.0.0",
        "real_traffic_enabled": real_traffic_enabled,
        "mode": "clean_real_traffic_capture" if real_traffic_enabled else "no_data"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "redis_connected": redis_client is not None,
        "real_traffic_enabled": real_traffic_enabled,
        "components": {
            "packet_capture": "active" if real_traffic_enabled else "disabled",
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
        "real_traffic_enabled": real_traffic_enabled,
        "components": {
            "packet_capture": "active" if real_traffic_enabled else "disabled",
            "threat_detector": "active",
            "dashboard": "active"
        },
        "statistics": threat_stats
    }

@app.get("/api/v1/events")
async def get_recent_events(limit: int = 50):
    """Get recent events"""
    try:
        if redis_client:
            events = redis_client.lrange('recent_events', 0, limit - 1)
            return [json.loads(event) for event in events]
        else:
            return []
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return []

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Clean real traffic dashboard"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Clean Real Traffic Cybersecurity Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .stat-value {{ font-size: 2em; font-weight: bold; color: #3498db; }}
            .stat-label {{ color: #7f8c8d; margin-top: 5px; }}
            .threat {{ color: #e74c3c; }}
            .normal {{ color: #27ae60; }}
            .real-traffic {{ color: #9b59b6; }}
            .events {{ background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .event-item {{ padding: 15px; margin: 10px 0; border-radius: 5px; }}
            .refresh-btn {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }}
            .refresh-btn:hover {{ background: #2980b9; }}
            .traffic-indicator {{ background: {'#d5f4e6' if real_traffic_enabled else '#ffeaa7'}; padding: 15px; border-radius: 5px; margin-bottom: 20px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Clean Real Traffic Cybersecurity Dashboard</h1>
                <p>Live network traffic monitoring - ONLY real packets from your system</p>
            </div>
            
            <div class="traffic-indicator">
                <h2>{'🟢 CLEAN REAL TRAFFIC CAPTURE ACTIVE' if real_traffic_enabled else '🟡 NO TRAFFIC CAPTURE'}</h2>
                <p>{'Monitoring ONLY real network traffic from your system' if real_traffic_enabled else 'No traffic capture - run with sudo to enable'}</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value" id="total-events">-</div>
                    <div class="stat-label">Total Events</div>
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
                    <div class="stat-value {'real-traffic' if real_traffic_enabled else 'normal'}" id="traffic-mode">-</div>
                    <div class="stat-label">Traffic Mode</div>
                </div>
            </div>
            
            <div class="events">
                <h2>Recent Real Network Events</h2>
                <button class="refresh-btn" onclick="loadData()">Refresh</button>
                <div id="events-list">Loading...</div>
            </div>
        </div>
        
        <script>
            async function loadData() {{
                try {{
                    const statusResponse = await fetch('/api/v1/status');
                    const status = await statusResponse.json();
                    
                    document.getElementById('total-events').textContent = status.statistics.total_events;
                    document.getElementById('threats-detected').textContent = status.statistics.threats_detected;
                    document.getElementById('threat-rate').textContent = 
                        status.statistics.total_events > 0 ? 
                        (status.statistics.threats_detected / status.statistics.total_events * 100).toFixed(1) + '%' : '0%';
                    document.getElementById('traffic-mode').textContent = status.real_traffic_enabled ? 'REAL' : 'NONE';
                    
                    const eventsResponse = await fetch('/api/v1/events?limit=10');
                    const events = await eventsResponse.json();
                    
                    const eventsList = document.getElementById('events-list');
                    if (events.length === 0) {{
                        eventsList.innerHTML = '<div style="text-align: center; padding: 20px; color: #666;">No real traffic captured yet. Try browsing the web to generate network activity.</div>';
                    }} else {{
                        eventsList.innerHTML = events.map(event => `
                            <div class="event-item" style="border-left: 4px solid ${{event.is_threat ? '#e74c3c' : '#27ae60'}}; background: ${{event.is_threat ? '#ffeaea' : '#f0fff0'}};">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <strong>${{new Date(event.timestamp * 1000).toLocaleTimeString()}}</strong>
                                        <div style="font-size: 1.2em; font-weight: bold; color: ${{event.is_threat ? '#e74c3c' : '#27ae60'}};">
                                            ${{event.website_name || event.dst_ip}}
                                        </div>
                                        <div style="color: #666; font-size: 0.9em;">
                                            ${{event.src_ip}} → ${{event.dst_ip}} (${{event.protocol}})
                                        </div>
                                        ${{event.threat_reason ? `<div style="color: #e67e22; font-size: 0.9em; margin-top: 5px;">
                                            <strong>Threat:</strong> ${{event.threat_reason}}
                                        </div>` : ''}}
                                        <div style="color: #666; font-size: 0.8em; margin-top: 5px;">
                                            🟢 Real Traffic • Size: ${{event.packet_size}} bytes
                                        </div>
                                    </div>
                                    <div style="text-align: right;">
                                        <div class="${{event.is_threat ? 'threat' : 'normal'}}" style="font-weight: bold; font-size: 1.1em;">
                                            ${{event.is_threat ? '🚨 THREAT' : '✅ SAFE'}}
                                        </div>
                                        <div style="font-size: 0.9em; color: #666;">
                                            Score: ${{(event.threat_score * 100).toFixed(1)}}%
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `).join('');
                    }}
                    
                }} catch (error) {{
                    console.error('Error loading data:', error);
                    document.getElementById('events-list').innerHTML = 'Error loading data';
                }}
            }}
            
            loadData();
            setInterval(loadData, 3000);
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
        "clean_real_traffic:app",
        host="0.0.0.0",
        port=8007,
        reload=True,
        log_level="info"
    )


