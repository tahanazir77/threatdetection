"""
Real-time stream processing for threat detection
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from collections import deque
import redis.asyncio as redis
from loguru import logger

from ..ai_models.threat_detector import ThreatDetector, ThreatDetectionResult
from ..data_collection.network_monitor import NetworkPacket, SystemMetrics

@dataclass
class ProcessedEvent:
    """Processed security event"""
    timestamp: float
    event_type: str
    threat_result: Optional[ThreatDetectionResult]
    packet_data: Optional[Dict]
    metrics_data: Optional[Dict]
    severity: str
    processed: bool = False

class StreamProcessor:
    """Real-time stream processing for threat detection"""
    
    def __init__(self, settings):
        self.settings = settings
        self.is_running = False
        self.redis_client = None
        self.threat_detector = ThreatDetector(settings)
        self.event_queue = asyncio.Queue()
        self.processed_events = deque(maxlen=1000)
        self.callbacks: List[Callable] = []
        
        # Performance tracking
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'processing_time': 0.0,
            'last_update': time.time()
        }
        
    async def start(self):
        """Start stream processing"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.from_url(self.settings.redis_url)
            await self.redis_client.ping()
            
            # Load pre-trained models if available
            try:
                self.threat_detector.load_models(self.settings.model_path)
                logger.info("Loaded pre-trained models")
            except Exception as e:
                logger.warning(f"Could not load pre-trained models: {e}")
            
            # Start processing
            self.is_running = True
            
            # Start main processing loop
            asyncio.create_task(self._main_processing_loop())
            
            # Start data aggregation
            asyncio.create_task(self._data_aggregation_loop())
            
            # Start performance monitoring
            asyncio.create_task(self._performance_monitoring_loop())
            
            logger.info("Stream processor started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start stream processor: {e}")
            raise
    
    async def stop(self):
        """Stop stream processing"""
        self.is_running = False
        if self.redis_client:
            await self.redis_client.close()
        logger.info("Stream processor stopped")
    
    def is_running(self) -> bool:
        """Check if processor is running"""
        return self.is_running
    
    async def _main_processing_loop(self):
        """Main processing loop"""
        while self.is_running:
            try:
                # Get recent data from Redis
                packets = await self._get_recent_packets()
                metrics = await self._get_recent_metrics()
                
                # Process data pairs
                await self._process_data_pairs(packets, metrics)
                
                # Small delay to prevent excessive CPU usage
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in main processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _get_recent_packets(self) -> List[Dict]:
        """Get recent packets from Redis"""
        try:
            if not self.redis_client:
                return []
            
            packets = await self.redis_client.lrange("recent_packets", 0, 9)  # Last 10 packets
            return [json.loads(packet) for packet in packets]
            
        except Exception as e:
            logger.error(f"Error getting recent packets: {e}")
            return []
    
    async def _get_recent_metrics(self) -> List[Dict]:
        """Get recent metrics from Redis"""
        try:
            if not self.redis_client:
                return []
            
            metrics = await self.redis_client.lrange("recent_metrics", 0, 4)  # Last 5 metrics
            return [json.loads(metric) for metric in metrics]
            
        except Exception as e:
            logger.error(f"Error getting recent metrics: {e}")
            return []
    
    async def _process_data_pairs(self, packets: List[Dict], metrics: List[Dict]):
        """Process packet and metrics data pairs"""
        try:
            # Get the most recent metrics
            if not metrics:
                return
            
            latest_metrics = metrics[0]
            
            # Process each packet with the latest metrics
            for packet in packets:
                # Check if we've already processed this packet
                packet_id = f"{packet.get('timestamp')}_{packet.get('src_ip')}_{packet.get('dst_ip')}"
                
                if await self._is_already_processed(packet_id):
                    continue
                
                # Process the packet
                await self._process_single_event(packet, latest_metrics, packet_id)
                
        except Exception as e:
            logger.error(f"Error processing data pairs: {e}")
    
    async def _process_single_event(self, packet: Dict, metrics: Dict, event_id: str):
        """Process a single event"""
        try:
            start_time = time.time()
            
            # Perform threat detection
            threat_result = self.threat_detector.detect_threat(packet, metrics)
            
            # Create processed event
            processed_event = ProcessedEvent(
                timestamp=time.time(),
                event_type="network_packet",
                threat_result=threat_result,
                packet_data=packet,
                metrics_data=metrics,
                severity=self._determine_severity(threat_result),
                processed=True
            )
            
            # Store in processed events
            self.processed_events.append(processed_event)
            
            # Store in Redis
            await self._store_processed_event(processed_event, event_id)
            
            # Update statistics
            self.stats['events_processed'] += 1
            if threat_result.is_threat:
                self.stats['threats_detected'] += 1
            
            processing_time = time.time() - start_time
            self.stats['processing_time'] = processing_time
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    await callback(processed_event)
                except Exception as e:
                    logger.error(f"Error in event callback: {e}")
            
            logger.debug(f"Processed event {event_id} in {processing_time:.3f}s")
            
        except Exception as e:
            logger.error(f"Error processing single event: {e}")
    
    async def _is_already_processed(self, event_id: str) -> bool:
        """Check if event has already been processed"""
        try:
            if not self.redis_client:
                return False
            
            exists = await self.redis_client.exists(f"processed:{event_id}")
            return bool(exists)
            
        except Exception as e:
            logger.error(f"Error checking if event is processed: {e}")
            return False
    
    async def _store_processed_event(self, event: ProcessedEvent, event_id: str):
        """Store processed event in Redis"""
        try:
            if not self.redis_client:
                return
            
            # Store event data
            event_data = {
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'severity': event.severity,
                'threat_result': asdict(event.threat_result) if event.threat_result else None,
                'packet_data': event.packet_data,
                'metrics_data': event.metrics_data
            }
            
            # Store with TTL
            await self.redis_client.setex(
                f"processed:{event_id}",
                3600,  # 1 hour TTL
                json.dumps(event_data)
            )
            
            # Add to recent events list
            await self.redis_client.lpush("recent_events", json.dumps(event_data))
            await self.redis_client.ltrim("recent_events", 0, 999)  # Keep last 1000
            
            # Store threat events separately
            if event.threat_result and event.threat_result.is_threat:
                await self.redis_client.lpush("threat_events", json.dumps(event_data))
                await self.redis_client.ltrim("threat_events", 0, 499)  # Keep last 500
            
        except Exception as e:
            logger.error(f"Error storing processed event: {e}")
    
    def _determine_severity(self, threat_result: ThreatDetectionResult) -> str:
        """Determine event severity based on threat result"""
        if not threat_result.is_threat:
            return "low"
        
        if threat_result.threat_score < 0.5:
            return "medium"
        elif threat_result.threat_score < 0.8:
            return "high"
        else:
            return "critical"
    
    async def _data_aggregation_loop(self):
        """Aggregate data for analysis"""
        while self.is_running:
            try:
                # Aggregate threat statistics
                await self._aggregate_threat_stats()
                
                # Clean up old data
                await self._cleanup_old_data()
                
                # Wait before next aggregation
                await asyncio.sleep(60)  # Every minute
                
            except Exception as e:
                logger.error(f"Error in data aggregation: {e}")
                await asyncio.sleep(30)
    
    async def _aggregate_threat_stats(self):
        """Aggregate threat statistics"""
        try:
            if not self.redis_client:
                return
            
            # Get recent threat events
            threat_events = await self.redis_client.lrange("threat_events", 0, 99)
            
            if not threat_events:
                return
            
            # Calculate statistics
            threat_types = {}
            severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            
            for event_json in threat_events:
                event = json.loads(event_json)
                threat_result = event.get('threat_result', {})
                
                if threat_result:
                    threat_type = threat_result.get('threat_type', 'unknown')
                    threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                
                severity = event.get('severity', 'low')
                severity_counts[severity] += 1
            
            # Store aggregated stats
            stats_data = {
                'timestamp': time.time(),
                'threat_types': threat_types,
                'severity_counts': severity_counts,
                'total_threats': len(threat_events)
            }
            
            await self.redis_client.setex(
                "threat_stats",
                3600,  # 1 hour TTL
                json.dumps(stats_data)
            )
            
        except Exception as e:
            logger.error(f"Error aggregating threat stats: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old data to prevent memory issues"""
        try:
            if not self.redis_client:
                return
            
            # Clean up old processed events (older than 1 hour)
            current_time = time.time()
            cutoff_time = current_time - 3600  # 1 hour ago
            
            # This is a simplified cleanup - in production, you'd want more sophisticated cleanup
            logger.debug("Performing data cleanup")
            
        except Exception as e:
            logger.error(f"Error in data cleanup: {e}")
    
    async def _performance_monitoring_loop(self):
        """Monitor processing performance"""
        while self.is_running:
            try:
                # Update performance stats
                self.stats['last_update'] = time.time()
                
                # Log performance metrics
                if self.stats['events_processed'] > 0:
                    avg_processing_time = self.stats['processing_time']
                    threat_rate = self.stats['threats_detected'] / self.stats['events_processed']
                    
                    logger.info(
                        f"Performance: {self.stats['events_processed']} events processed, "
                        f"{self.stats['threats_detected']} threats detected, "
                        f"threat rate: {threat_rate:.2%}, "
                        f"avg processing time: {avg_processing_time:.3f}s"
                    )
                
                # Wait before next monitoring cycle
                await asyncio.sleep(300)  # Every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in performance monitoring: {e}")
                await asyncio.sleep(60)
    
    def add_callback(self, callback: Callable):
        """Add callback for processed events"""
        self.callbacks.append(callback)
    
    async def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent processed events"""
        try:
            if not self.redis_client:
                return []
            
            events = await self.redis_client.lrange("recent_events", 0, limit - 1)
            return [json.loads(event) for event in events]
            
        except Exception as e:
            logger.error(f"Error getting recent events: {e}")
            return []
    
    async def get_threat_events(self, limit: int = 50) -> List[Dict]:
        """Get recent threat events"""
        try:
            if not self.redis_client:
                return []
            
            events = await self.redis_client.lrange("threat_events", 0, limit - 1)
            return [json.loads(event) for event in events]
            
        except Exception as e:
            logger.error(f"Error getting threat events: {e}")
            return []
    
    async def get_threat_stats(self) -> Dict:
        """Get aggregated threat statistics"""
        try:
            if not self.redis_client:
                return {}
            
            stats_json = await self.redis_client.get("threat_stats")
            if stats_json:
                return json.loads(stats_json)
            return {}
            
        except Exception as e:
            logger.error(f"Error getting threat stats: {e}")
            return {}
    
    def get_performance_stats(self) -> Dict:
        """Get current performance statistics"""
        return self.stats.copy()
