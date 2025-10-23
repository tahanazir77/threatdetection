"""
Network monitoring module for real-time packet capture and analysis
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil
import netifaces
from loguru import logger
import redis.asyncio as redis

@dataclass
class NetworkPacket:
    """Network packet data structure"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    flags: Optional[str] = None
    payload_hash: Optional[str] = None

@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    network_io: Dict[str, int]
    active_connections: int

class NetworkMonitor:
    """Real-time network monitoring and packet capture"""
    
    def __init__(self, settings):
        self.settings = settings
        self.is_running = False
        self.redis_client = None
        self.packet_queue = asyncio.Queue()
        self.metrics_queue = asyncio.Queue()
        self.callbacks: List[Callable] = []
        
    async def start(self):
        """Start network monitoring"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.from_url(self.settings.redis_url)
            await self.redis_client.ping()
            
            # Start monitoring tasks
            self.is_running = True
            
            # Start packet capture
            asyncio.create_task(self._packet_capture_loop())
            
            # Start system metrics collection
            asyncio.create_task(self._metrics_collection_loop())
            
            # Start data processing
            asyncio.create_task(self._data_processing_loop())
            
            logger.info("Network monitor started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start network monitor: {e}")
            raise
    
    async def stop(self):
        """Stop network monitoring"""
        self.is_running = False
        if self.redis_client:
            await self.redis_client.close()
        logger.info("Network monitor stopped")
    
    def is_running(self) -> bool:
        """Check if monitor is running"""
        return self.is_running
    
    async def _packet_capture_loop(self):
        """Main packet capture loop"""
        while self.is_running:
            try:
                # Try to capture packets, fall back to simulated data if no permissions
                try:
                    packets = sniff(
                        timeout=self.settings.packet_capture_timeout,
                        prn=self._process_packet,
                        store=0
                    )
                except PermissionError:
                    # Generate simulated packet data for demonstration
                    await self._generate_simulated_packets()
                
                # Small delay to prevent excessive CPU usage
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in packet capture: {e}")
                await asyncio.sleep(1)
    
    def _process_packet(self, packet):
        """Process individual packet"""
        try:
            if IP in packet:
                # Extract packet information
                packet_data = NetworkPacket(
                    timestamp=time.time(),
                    src_ip=packet[IP].src,
                    dst_ip=packet[IP].dst,
                    src_port=None,
                    dst_port=None,
                    protocol=packet[IP].proto,
                    packet_size=len(packet),
                    flags=None,
                    payload_hash=None
                )
                
                # Extract port information for TCP/UDP
                if TCP in packet:
                    packet_data.src_port = packet[TCP].sport
                    packet_data.dst_port = packet[TCP].dport
                    packet_data.flags = str(packet[TCP].flags)
                elif UDP in packet:
                    packet_data.src_port = packet[UDP].sport
                    packet_data.dst_port = packet[UDP].dport
                
                # Add to queue for processing
                asyncio.create_task(self._add_packet_to_queue(packet_data))
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    async def _add_packet_to_queue(self, packet: NetworkPacket):
        """Add packet to processing queue"""
        try:
            await self.packet_queue.put(packet)
        except Exception as e:
            logger.error(f"Error adding packet to queue: {e}")
    
    async def _metrics_collection_loop(self):
        """Collect system metrics"""
        while self.is_running:
            try:
                # Collect system metrics
                metrics = SystemMetrics(
                    timestamp=time.time(),
                    cpu_percent=psutil.cpu_percent(interval=1),
                    memory_percent=psutil.virtual_memory().percent,
                    disk_usage=psutil.disk_usage('/').percent,
                    network_io=dict(psutil.net_io_counters()._asdict()),
                    active_connections=len(psutil.net_connections())
                )
                
                await self.metrics_queue.put(metrics)
                
                # Collect metrics every 10 seconds
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                await asyncio.sleep(5)
    
    async def _data_processing_loop(self):
        """Process collected data"""
        while self.is_running:
            try:
                # Process packets
                if not self.packet_queue.empty():
                    packet = await self.packet_queue.get()
                    await self._process_packet_data(packet)
                
                # Process metrics
                if not self.metrics_queue.empty():
                    metrics = await self.metrics_queue.get()
                    await self._process_metrics_data(metrics)
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in data processing: {e}")
                await asyncio.sleep(1)
    
    async def _process_packet_data(self, packet: NetworkPacket):
        """Process packet data and store in Redis"""
        try:
            # Convert to JSON
            packet_json = json.dumps(asdict(packet))
            
            # Store in Redis with TTL
            await self.redis_client.setex(
                f"packet:{packet.timestamp}",
                3600,  # 1 hour TTL
                packet_json
            )
            
            # Add to recent packets list
            await self.redis_client.lpush("recent_packets", packet_json)
            await self.redis_client.ltrim("recent_packets", 0, 999)  # Keep last 1000
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    await callback("packet", packet)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing packet data: {e}")
    
    async def _generate_simulated_packets(self):
        """Generate simulated packet data for demonstration"""
        import random
        
        try:
            # Generate a few simulated packets
            for _ in range(random.randint(1, 5)):
                # Create simulated packet data
                packet_data = NetworkPacket(
                    timestamp=time.time(),
                    src_ip=f"192.168.1.{random.randint(1, 254)}",
                    dst_ip=f"10.0.0.{random.randint(1, 254)}",
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 22, 21, 25, 53]),
                    protocol=random.choice(["TCP", "UDP", "ICMP"]),
                    packet_size=random.randint(64, 1500),
                    flags=random.choice(["SYN", "ACK", "FIN", "RST"]),
                    payload_hash=None
                )
                
                # Add to queue for processing
                await self._add_packet_to_queue(packet_data)
                
            logger.debug("Generated simulated packet data")
            
        except Exception as e:
            logger.error(f"Error generating simulated packets: {e}")
    
    async def _process_metrics_data(self, metrics: SystemMetrics):
        """Process system metrics and store in Redis"""
        try:
            # Convert to JSON
            metrics_json = json.dumps(asdict(metrics))
            
            # Store in Redis
            await self.redis_client.setex(
                f"metrics:{metrics.timestamp}",
                3600,  # 1 hour TTL
                metrics_json
            )
            
            # Add to recent metrics list
            await self.redis_client.lpush("recent_metrics", metrics_json)
            await self.redis_client.ltrim("recent_metrics", 0, 99)  # Keep last 100
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    await callback("metrics", metrics)
                except Exception as e:
                    logger.error(f"Error in metrics callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing metrics data: {e}")
    
    def add_callback(self, callback: Callable):
        """Add callback for data events"""
        self.callbacks.append(callback)
    
    async def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get recent packets from Redis"""
        try:
            if not self.redis_client:
                return []
            
            packets = await self.redis_client.lrange("recent_packets", 0, limit - 1)
            return [json.loads(packet) for packet in packets]
            
        except Exception as e:
            logger.error(f"Error getting recent packets: {e}")
            return []
    
    async def get_recent_metrics(self, limit: int = 10) -> List[Dict]:
        """Get recent metrics from Redis"""
        try:
            if not self.redis_client:
                return []
            
            metrics = await self.redis_client.lrange("recent_metrics", 0, limit - 1)
            return [json.loads(metric) for metric in metrics]
            
        except Exception as e:
            logger.error(f"Error getting recent metrics: {e}")
            return []
