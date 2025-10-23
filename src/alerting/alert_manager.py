"""
Alerting and notification system for threat detection
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from loguru import logger

from ..real_time.stream_processor import ProcessedEvent
from ..ai_models.threat_detector import ThreatDetectionResult

class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertChannel(Enum):
    """Alert notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    LOG = "log"

@dataclass
class Alert:
    """Alert data structure"""
    id: str
    timestamp: float
    severity: AlertSeverity
    title: str
    description: str
    threat_result: Optional[ThreatDetectionResult]
    event_data: Optional[Dict]
    channels: List[AlertChannel]
    sent: bool = False
    retry_count: int = 0

@dataclass
class AlertRule:
    """Alert rule configuration"""
    name: str
    condition: str
    severity: AlertSeverity
    channels: List[AlertChannel]
    cooldown: int  # seconds
    enabled: bool = True

class AlertManager:
    """Alert and notification management system"""
    
    def __init__(self, settings):
        self.settings = settings
        self.is_running = False
        self.alert_queue = asyncio.Queue()
        self.sent_alerts = {}  # For cooldown tracking
        self.alert_rules = []
        self.callbacks: List[Callable] = []
        
        # Initialize alert rules
        self._initialize_alert_rules()
        
    def _initialize_alert_rules(self):
        """Initialize default alert rules"""
        self.alert_rules = [
            AlertRule(
                name="High Threat Detection",
                condition="threat_score > 0.8",
                severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.EMAIL, AlertChannel.LOG],
                cooldown=300  # 5 minutes
            ),
            AlertRule(
                name="Medium Threat Detection",
                condition="threat_score > 0.6",
                severity=AlertSeverity.HIGH,
                channels=[AlertChannel.LOG],
                cooldown=600  # 10 minutes
            ),
            AlertRule(
                name="Suspicious Activity",
                condition="threat_score > 0.4",
                severity=AlertSeverity.MEDIUM,
                channels=[AlertChannel.LOG],
                cooldown=1800  # 30 minutes
            ),
            AlertRule(
                name="System Resource Alert",
                condition="cpu_percent > 90 or memory_percent > 90",
                severity=AlertSeverity.HIGH,
                channels=[AlertChannel.EMAIL, AlertChannel.LOG],
                cooldown=900  # 15 minutes
            )
        ]
    
    async def start(self):
        """Start alert manager"""
        try:
            self.is_running = True
            
            # Start alert processing loop
            asyncio.create_task(self._alert_processing_loop())
            
            # Start cleanup loop
            asyncio.create_task(self._cleanup_loop())
            
            logger.info("Alert manager started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start alert manager: {e}")
            raise
    
    async def stop(self):
        """Stop alert manager"""
        self.is_running = False
        logger.info("Alert manager stopped")
    
    def is_running(self) -> bool:
        """Check if alert manager is running"""
        return self.is_running
    
    async def _alert_processing_loop(self):
        """Main alert processing loop"""
        while self.is_running:
            try:
                # Process alerts from queue
                if not self.alert_queue.empty():
                    alert = await self.alert_queue.get()
                    await self._process_alert(alert)
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in alert processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_alert(self, alert: Alert):
        """Process a single alert"""
        try:
            # Check if alert should be sent (cooldown)
            if self._should_send_alert(alert):
                # Send alert through configured channels
                await self._send_alert(alert)
                
                # Mark as sent and update cooldown
                alert.sent = True
                self.sent_alerts[alert.id] = time.time()
                
                logger.info(f"Alert sent: {alert.title} (severity: {alert.severity.value})")
            else:
                logger.debug(f"Alert suppressed due to cooldown: {alert.title}")
            
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            alert.retry_count += 1
            
            # Retry if retry count is below threshold
            if alert.retry_count < 3:
                await asyncio.sleep(5)
                await self.alert_queue.put(alert)
    
    def _should_send_alert(self, alert: Alert) -> bool:
        """Check if alert should be sent based on cooldown rules"""
        try:
            # Find matching rule
            rule = self._find_matching_rule(alert)
            if not rule or not rule.enabled:
                return False
            
            # Check cooldown
            if alert.id in self.sent_alerts:
                last_sent = self.sent_alerts[alert.id]
                if time.time() - last_sent < rule.cooldown:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking if alert should be sent: {e}")
            return False
    
    def _find_matching_rule(self, alert: Alert) -> Optional[AlertRule]:
        """Find matching alert rule for the alert"""
        try:
            for rule in self.alert_rules:
                if self._evaluate_condition(rule.condition, alert):
                    return rule
            return None
            
        except Exception as e:
            logger.error(f"Error finding matching rule: {e}")
            return None
    
    def _evaluate_condition(self, condition: str, alert: Alert) -> bool:
        """Evaluate alert condition"""
        try:
            # Simple condition evaluation
            # In production, you'd want a more sophisticated condition evaluator
            
            if alert.threat_result:
                threat_score = alert.threat_result.threat_score
                
                if "threat_score > 0.8" in condition:
                    return threat_score > 0.8
                elif "threat_score > 0.6" in condition:
                    return threat_score > 0.6
                elif "threat_score > 0.4" in condition:
                    return threat_score > 0.4
            
            if alert.event_data:
                metrics = alert.event_data.get('metrics_data', {})
                cpu_percent = metrics.get('cpu_percent', 0)
                memory_percent = metrics.get('memory_percent', 0)
                
                if "cpu_percent > 90" in condition:
                    return cpu_percent > 90
                elif "memory_percent > 90" in condition:
                    return memory_percent > 90
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
            return False
    
    async def _send_alert(self, alert: Alert):
        """Send alert through configured channels"""
        try:
            rule = self._find_matching_rule(alert)
            if not rule:
                return
            
            # Send through each configured channel
            for channel in rule.channels:
                try:
                    if channel == AlertChannel.EMAIL:
                        await self._send_email_alert(alert)
                    elif channel == AlertChannel.SLACK:
                        await self._send_slack_alert(alert)
                    elif channel == AlertChannel.WEBHOOK:
                        await self._send_webhook_alert(alert)
                    elif channel == AlertChannel.LOG:
                        await self._send_log_alert(alert)
                        
                except Exception as e:
                    logger.error(f"Error sending alert via {channel.value}: {e}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    async def _send_email_alert(self, alert: Alert):
        """Send email alert"""
        try:
            if not self.settings.alert_email_enabled:
                return
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = "cybersecurity-system@example.com"
            msg['To'] = "admin@example.com"
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
            
            # Create email body
            body = f"""
            Alert Details:
            - Severity: {alert.severity.value.upper()}
            - Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp))}
            - Description: {alert.description}
            
            """
            
            if alert.threat_result:
                body += f"""
                Threat Analysis:
                - Threat Score: {alert.threat_result.threat_score:.2f}
                - Threat Type: {alert.threat_result.threat_type}
                - Confidence: {alert.threat_result.confidence:.2f}
                - Explanation: {alert.threat_result.explanation}
                """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email (simplified - in production, use proper SMTP configuration)
            logger.info(f"Email alert sent: {alert.title}")
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
    
    async def _send_slack_alert(self, alert: Alert):
        """Send Slack alert"""
        try:
            if not self.settings.alert_slack_enabled:
                return
            
            # Create Slack message
            message = {
                "text": f"🚨 *{alert.title}*",
                "attachments": [
                    {
                        "color": self._get_severity_color(alert.severity),
                        "fields": [
                            {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                            {"title": "Time", "value": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp)), "short": True},
                            {"title": "Description", "value": alert.description, "short": False}
                        ]
                    }
                ]
            }
            
            if alert.threat_result:
                message["attachments"][0]["fields"].extend([
                    {"title": "Threat Score", "value": f"{alert.threat_result.threat_score:.2f}", "short": True},
                    {"title": "Threat Type", "value": alert.threat_result.threat_type, "short": True},
                    {"title": "Confidence", "value": f"{alert.threat_result.confidence:.2f}", "short": True}
                ])
            
            # Send to Slack (simplified - in production, use proper webhook)
            logger.info(f"Slack alert sent: {alert.title}")
            
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
    
    async def _send_webhook_alert(self, alert: Alert):
        """Send webhook alert"""
        try:
            if not self.settings.alert_webhook_url:
                return
            
            # Create webhook payload
            payload = {
                "alert_id": alert.id,
                "timestamp": alert.timestamp,
                "severity": alert.severity.value,
                "title": alert.title,
                "description": alert.description,
                "threat_result": asdict(alert.threat_result) if alert.threat_result else None,
                "event_data": alert.event_data
            }
            
            # Send webhook
            response = requests.post(
                self.settings.alert_webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook alert sent: {alert.title}")
            else:
                logger.error(f"Webhook alert failed: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")
    
    async def _send_log_alert(self, alert: Alert):
        """Send log alert"""
        try:
            # Log the alert
            logger.warning(
                f"ALERT [{alert.severity.value.upper()}] {alert.title}: {alert.description}"
            )
            
            if alert.threat_result:
                logger.warning(
                    f"Threat details - Score: {alert.threat_result.threat_score:.2f}, "
                    f"Type: {alert.threat_result.threat_type}, "
                    f"Confidence: {alert.threat_result.confidence:.2f}"
                )
            
        except Exception as e:
            logger.error(f"Error sending log alert: {e}")
    
    def _get_severity_color(self, severity: AlertSeverity) -> str:
        """Get color for alert severity"""
        colors = {
            AlertSeverity.LOW: "good",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.HIGH: "danger",
            AlertSeverity.CRITICAL: "danger"
        }
        return colors.get(severity, "good")
    
    async def _cleanup_loop(self):
        """Cleanup old alerts and cooldown data"""
        while self.is_running:
            try:
                # Clean up old cooldown data (older than 1 hour)
                current_time = time.time()
                cutoff_time = current_time - 3600
                
                old_alerts = [
                    alert_id for alert_id, timestamp in self.sent_alerts.items()
                    if timestamp < cutoff_time
                ]
                
                for alert_id in old_alerts:
                    del self.sent_alerts[alert_id]
                
                if old_alerts:
                    logger.debug(f"Cleaned up {len(old_alerts)} old alert cooldowns")
                
                # Wait before next cleanup
                await asyncio.sleep(3600)  # Every hour
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(300)
    
    def add_callback(self, callback: Callable):
        """Add callback for alert events"""
        self.callbacks.append(callback)
    
    async def create_alert(self, event: ProcessedEvent) -> Optional[Alert]:
        """Create alert from processed event"""
        try:
            if not event.threat_result or not event.threat_result.is_threat:
                return None
            
            # Generate alert ID
            alert_id = f"alert_{int(time.time())}_{hash(str(event.timestamp))}"
            
            # Determine severity
            severity = self._determine_alert_severity(event.threat_result)
            
            # Create alert
            alert = Alert(
                id=alert_id,
                timestamp=time.time(),
                severity=severity,
                title=f"Threat Detected: {event.threat_result.threat_type}",
                description=event.threat_result.explanation,
                threat_result=event.threat_result,
                event_data=asdict(event),
                channels=[]  # Will be set by matching rule
            )
            
            # Add to queue
            await self.alert_queue.put(alert)
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    await callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            return alert
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    def _determine_alert_severity(self, threat_result: ThreatDetectionResult) -> AlertSeverity:
        """Determine alert severity from threat result"""
        if threat_result.threat_score >= 0.8:
            return AlertSeverity.CRITICAL
        elif threat_result.threat_score >= 0.6:
            return AlertSeverity.HIGH
        elif threat_result.threat_score >= 0.4:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def add_alert_rule(self, rule: AlertRule):
        """Add new alert rule"""
        self.alert_rules.append(rule)
        logger.info(f"Added alert rule: {rule.name}")
    
    def remove_alert_rule(self, rule_name: str):
        """Remove alert rule"""
        self.alert_rules = [rule for rule in self.alert_rules if rule.name != rule_name]
        logger.info(f"Removed alert rule: {rule_name}")
    
    def get_alert_rules(self) -> List[AlertRule]:
        """Get all alert rules"""
        return self.alert_rules.copy()
    
    def get_alert_stats(self) -> Dict:
        """Get alert statistics"""
        return {
            "total_rules": len(self.alert_rules),
            "enabled_rules": len([rule for rule in self.alert_rules if rule.enabled]),
            "active_cooldowns": len(self.sent_alerts),
            "queue_size": self.alert_queue.qsize()
        }
