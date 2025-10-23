"""
Web dashboard routes for the Cybersecurity System
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import Dict, List, Optional
import json
import time
from loguru import logger

from ..real_time.stream_processor import StreamProcessor
from ..alerting.alert_manager import AlertManager
from ..data_collection.network_monitor import NetworkMonitor

router = APIRouter()

# Global instances (will be injected)
stream_processor: Optional[StreamProcessor] = None
alert_manager: Optional[AlertManager] = None
network_monitor: Optional[NetworkMonitor] = None

def get_stream_processor() -> StreamProcessor:
    """Get stream processor instance"""
    if stream_processor is None:
        raise HTTPException(status_code=503, detail="Stream processor not available")
    return stream_processor

def get_alert_manager() -> AlertManager:
    """Get alert manager instance"""
    if alert_manager is None:
        raise HTTPException(status_code=503, detail="Alert manager not available")
    return alert_manager

def get_network_monitor() -> NetworkMonitor:
    """Get network monitor instance"""
    if network_monitor is None:
        raise HTTPException(status_code=503, detail="Network monitor not available")
    return network_monitor

@router.get("/", response_class=HTMLResponse)
async def dashboard_home():
    """Main dashboard page"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cybersecurity System Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                text-align: center;
            }
            .dashboard-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            .card {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .card h3 {
                margin-top: 0;
                color: #333;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }
            .metric {
                display: flex;
                justify-content: space-between;
                margin: 10px 0;
                padding: 10px;
                background: #f8f9fa;
                border-radius: 5px;
            }
            .metric-value {
                font-weight: bold;
                color: #667eea;
            }
            .threat-level {
                padding: 5px 10px;
                border-radius: 15px;
                color: white;
                font-weight: bold;
                text-align: center;
                margin: 5px 0;
            }
            .threat-low { background-color: #28a745; }
            .threat-medium { background-color: #ffc107; color: #333; }
            .threat-high { background-color: #fd7e14; }
            .threat-critical { background-color: #dc3545; }
            .alert-item {
                padding: 10px;
                margin: 5px 0;
                border-left: 4px solid #667eea;
                background: #f8f9fa;
                border-radius: 0 5px 5px 0;
            }
            .alert-critical { border-left-color: #dc3545; }
            .alert-high { border-left-color: #fd7e14; }
            .alert-medium { border-left-color: #ffc107; }
            .alert-low { border-left-color: #28a745; }
            .status-indicator {
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                margin-right: 5px;
            }
            .status-running { background-color: #28a745; }
            .status-stopped { background-color: #dc3545; }
            .refresh-btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                margin: 10px 0;
            }
            .refresh-btn:hover {
                background: #5a6fd8;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ Generative AI-Based Smart Cybersecurity System</h1>
            <p>Real-time threat detection and monitoring dashboard</p>
        </div>

        <div class="dashboard-grid">
            <!-- System Status -->
            <div class="card">
                <h3>System Status</h3>
                <div id="system-status">
                    <div class="metric">
                        <span>Network Monitor</span>
                        <span class="metric-value" id="network-status">Loading...</span>
                    </div>
                    <div class="metric">
                        <span>Stream Processor</span>
                        <span class="metric-value" id="processor-status">Loading...</span>
                    </div>
                    <div class="metric">
                        <span>Alert Manager</span>
                        <span class="metric-value" id="alert-status">Loading...</span>
                    </div>
                </div>
            </div>

            <!-- Performance Metrics -->
            <div class="card">
                <h3>Performance Metrics</h3>
                <div id="performance-metrics">
                    <div class="metric">
                        <span>Events Processed</span>
                        <span class="metric-value" id="events-processed">0</span>
                    </div>
                    <div class="metric">
                        <span>Threats Detected</span>
                        <span class="metric-value" id="threats-detected">0</span>
                    </div>
                    <div class="metric">
                        <span>Processing Time</span>
                        <span class="metric-value" id="processing-time">0ms</span>
                    </div>
                    <div class="metric">
                        <span>Threat Rate</span>
                        <span class="metric-value" id="threat-rate">0%</span>
                    </div>
                </div>
            </div>

            <!-- Threat Statistics -->
            <div class="card">
                <h3>Threat Statistics</h3>
                <div id="threat-stats">
                    <div class="metric">
                        <span>Total Threats</span>
                        <span class="metric-value" id="total-threats">0</span>
                    </div>
                    <div class="metric">
                        <span>Critical</span>
                        <span class="metric-value" id="critical-threats">0</span>
                    </div>
                    <div class="metric">
                        <span>High</span>
                        <span class="metric-value" id="high-threats">0</span>
                    </div>
                    <div class="metric">
                        <span>Medium</span>
                        <span class="metric-value" id="medium-threats">0</span>
                    </div>
                </div>
            </div>

            <!-- Recent Alerts -->
            <div class="card">
                <h3>Recent Alerts</h3>
                <div id="recent-alerts">
                    <p>Loading alerts...</p>
                </div>
            </div>

            <!-- Network Activity Chart -->
            <div class="card">
                <h3>Network Activity</h3>
                <canvas id="network-chart" width="400" height="200"></canvas>
            </div>

            <!-- Threat Detection Chart -->
            <div class="card">
                <h3>Threat Detection</h3>
                <canvas id="threat-chart" width="400" height="200"></canvas>
            </div>
        </div>

        <button class="refresh-btn" onclick="refreshDashboard()">Refresh Dashboard</button>

        <script>
            let networkChart, threatChart;
            
            // Initialize charts
            function initCharts() {
                // Network Activity Chart
                const networkCtx = document.getElementById('network-chart').getContext('2d');
                networkChart = new Chart(networkCtx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Packets/sec',
                            data: [],
                            borderColor: '#667eea',
                            backgroundColor: 'rgba(102, 126, 234, 0.1)',
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });

                // Threat Detection Chart
                const threatCtx = document.getElementById('threat-chart').getContext('2d');
                threatChart = new Chart(threatCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Normal', 'Suspicious', 'Threats'],
                        datasets: [{
                            data: [100, 0, 0],
                            backgroundColor: ['#28a745', '#ffc107', '#dc3545']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            }

            // Refresh dashboard data
            async function refreshDashboard() {
                try {
                    // Get system status
                    const statusResponse = await fetch('/api/v1/status');
                    const status = await statusResponse.json();
                    updateSystemStatus(status);

                    // Get performance metrics
                    const perfResponse = await fetch('/api/v1/performance');
                    const performance = await perfResponse.json();
                    updatePerformanceMetrics(performance);

                    // Get threat statistics
                    const threatResponse = await fetch('/api/v1/threat-stats');
                    const threatStats = await threatResponse.json();
                    updateThreatStatistics(threatStats);

                    // Get recent alerts
                    const alertsResponse = await fetch('/api/v1/alerts');
                    const alerts = await alertsResponse.json();
                    updateRecentAlerts(alerts);

                    // Get recent events for charts
                    const eventsResponse = await fetch('/api/v1/events');
                    const events = await eventsResponse.json();
                    updateCharts(events);

                } catch (error) {
                    console.error('Error refreshing dashboard:', error);
                }
            }

            // Update system status
            function updateSystemStatus(status) {
                document.getElementById('network-status').innerHTML = 
                    `<span class="status-indicator ${status.network_monitor ? 'status-running' : 'status-stopped'}"></span>${status.network_monitor ? 'Running' : 'Stopped'}`;
                document.getElementById('processor-status').innerHTML = 
                    `<span class="status-indicator ${status.stream_processor ? 'status-running' : 'status-stopped'}"></span>${status.stream_processor ? 'Running' : 'Stopped'}`;
                document.getElementById('alert-status').innerHTML = 
                    `<span class="status-indicator ${status.alert_manager ? 'status-running' : 'status-stopped'}"></span>${status.alert_manager ? 'Running' : 'Stopped'}`;
            }

            // Update performance metrics
            function updatePerformanceMetrics(performance) {
                document.getElementById('events-processed').textContent = performance.events_processed || 0;
                document.getElementById('threats-detected').textContent = performance.threats_detected || 0;
                document.getElementById('processing-time').textContent = `${(performance.processing_time * 1000).toFixed(1)}ms`;
                
                const threatRate = performance.events_processed > 0 ? 
                    (performance.threats_detected / performance.events_processed * 100).toFixed(1) : 0;
                document.getElementById('threat-rate').textContent = `${threatRate}%`;
            }

            // Update threat statistics
            function updateThreatStatistics(stats) {
                document.getElementById('total-threats').textContent = stats.total_threats || 0;
                document.getElementById('critical-threats').textContent = stats.severity_counts?.critical || 0;
                document.getElementById('high-threats').textContent = stats.severity_counts?.high || 0;
                document.getElementById('medium-threats').textContent = stats.severity_counts?.medium || 0;
            }

            // Update recent alerts
            function updateRecentAlerts(alerts) {
                const alertsContainer = document.getElementById('recent-alerts');
                
                if (alerts.length === 0) {
                    alertsContainer.innerHTML = '<p>No recent alerts</p>';
                    return;
                }

                alertsContainer.innerHTML = alerts.map(alert => `
                    <div class="alert-item alert-${alert.severity}">
                        <strong>${alert.title}</strong><br>
                        <small>${new Date(alert.timestamp * 1000).toLocaleString()}</small><br>
                        <span>${alert.description}</span>
                    </div>
                `).join('');
            }

            // Update charts
            function updateCharts(events) {
                // Update network chart with recent events
                const now = new Date();
                const labels = [];
                const data = [];
                
                for (let i = 9; i >= 0; i--) {
                    const time = new Date(now.getTime() - i * 60000);
                    labels.push(time.toLocaleTimeString());
                    data.push(Math.floor(Math.random() * 100)); // Placeholder data
                }
                
                networkChart.data.labels = labels;
                networkChart.data.datasets[0].data = data;
                networkChart.update();

                // Update threat chart
                const normalCount = events.filter(e => !e.threat_result?.is_threat).length;
                const threatCount = events.filter(e => e.threat_result?.is_threat).length;
                const suspiciousCount = events.filter(e => e.threat_result?.threat_score > 0.3 && e.threat_result?.threat_score < 0.6).length;

                threatChart.data.datasets[0].data = [normalCount, suspiciousCount, threatCount];
                threatChart.update();
            }

            // Initialize dashboard
            document.addEventListener('DOMContentLoaded', function() {
                initCharts();
                refreshDashboard();
                
                // Auto-refresh every 30 seconds
                setInterval(refreshDashboard, 30000);
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/status")
async def get_system_status(
    network_monitor: NetworkMonitor = Depends(get_network_monitor),
    stream_processor: StreamProcessor = Depends(get_stream_processor),
    alert_manager: AlertManager = Depends(get_alert_manager)
):
    """Get system status"""
    try:
        return {
            "network_monitor": network_monitor.is_running(),
            "stream_processor": stream_processor.is_running(),
            "alert_manager": alert_manager.is_running(),
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail="Error getting system status")

@router.get("/performance")
async def get_performance_metrics(
    stream_processor: StreamProcessor = Depends(get_stream_processor)
):
    """Get performance metrics"""
    try:
        stats = stream_processor.get_performance_stats()
        return stats
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Error getting performance metrics")

@router.get("/threat-stats")
async def get_threat_statistics(
    stream_processor: StreamProcessor = Depends(get_stream_processor)
):
    """Get threat statistics"""
    try:
        stats = await stream_processor.get_threat_stats()
        return stats
    except Exception as e:
        logger.error(f"Error getting threat statistics: {e}")
        raise HTTPException(status_code=500, detail="Error getting threat statistics")

@router.get("/alerts")
async def get_recent_alerts(
    alert_manager: AlertManager = Depends(get_alert_manager)
):
    """Get recent alerts"""
    try:
        # This is a simplified version - in production, you'd want to store alerts in a database
        stats = alert_manager.get_alert_stats()
        return []  # Placeholder - would return actual alerts
    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
        raise HTTPException(status_code=500, detail="Error getting recent alerts")

@router.get("/events")
async def get_recent_events(
    stream_processor: StreamProcessor = Depends(get_stream_processor)
):
    """Get recent events"""
    try:
        events = await stream_processor.get_recent_events(limit=50)
        return events
    except Exception as e:
        logger.error(f"Error getting recent events: {e}")
        raise HTTPException(status_code=500, detail="Error getting recent events")

@router.get("/threats")
async def get_threat_events(
    stream_processor: StreamProcessor = Depends(get_stream_processor)
):
    """Get recent threat events"""
    try:
        threats = await stream_processor.get_threat_events(limit=20)
        return threats
    except Exception as e:
        logger.error(f"Error getting threat events: {e}")
        raise HTTPException(status_code=500, detail="Error getting threat events")

@router.get("/network/packets")
async def get_recent_packets(
    network_monitor: NetworkMonitor = Depends(get_network_monitor)
):
    """Get recent network packets"""
    try:
        packets = await network_monitor.get_recent_packets(limit=100)
        return packets
    except Exception as e:
        logger.error(f"Error getting recent packets: {e}")
        raise HTTPException(status_code=500, detail="Error getting recent packets")

@router.get("/network/metrics")
async def get_system_metrics(
    network_monitor: NetworkMonitor = Depends(get_network_monitor)
):
    """Get recent system metrics"""
    try:
        metrics = await network_monitor.get_recent_metrics(limit=10)
        return metrics
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        raise HTTPException(status_code=500, detail="Error getting system metrics")

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "1.0.0"
    }
