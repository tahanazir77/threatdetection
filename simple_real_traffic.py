#!/usr/bin/env python3
"""
Simple Real Traffic Capture Test
"""

import socket
import time
import json
from scapy.all import sniff, IP, TCP, UDP
import threading
import queue

# Global queue for captured packets
packet_queue = queue.Queue()

def packet_handler(packet):
    """Handle captured packets"""
    try:
        if IP in packet:
            packet_info = {
                'timestamp': time.time(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'packet_size': len(packet)
            }
            
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['protocol_name'] = 'TCP'
            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['protocol_name'] = 'UDP'
            
            packet_queue.put(packet_info)
            print(f"Captured: {packet_info['src_ip']} -> {packet_info['dst_ip']} ({packet_info.get('protocol_name', 'Unknown')})")
            
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_capture():
    """Start packet capture"""
    try:
        print("Starting packet capture...")
        sniff(prn=packet_handler, store=0, timeout=10)
    except Exception as e:
        print(f"Capture error: {e}")

def main():
    """Main function"""
    print("🛡️ Real Traffic Capture Test")
    print("=" * 40)
    
    # Try to start packet capture
    try:
        print("Attempting to capture real network traffic...")
        print("This requires root privileges on most systems.")
        print()
        
        # Start capture in a separate thread
        capture_thread = threading.Thread(target=start_capture, daemon=True)
        capture_thread.start()
        
        # Wait for packets
        print("Waiting for network traffic...")
        print("Try browsing the web or making network requests...")
        print()
        
        packet_count = 0
        start_time = time.time()
        
        while time.time() - start_time < 30:  # Run for 30 seconds
            try:
                packet = packet_queue.get(timeout=1)
                packet_count += 1
                
                print(f"Packet {packet_count}: {packet['src_ip']} -> {packet['dst_ip']} "
                      f"({packet.get('protocol_name', 'Unknown')}) - {packet['packet_size']} bytes")
                
                # Try to resolve destination IP
                try:
                    hostname = socket.gethostbyaddr(packet['dst_ip'])[0]
                    print(f"  -> Resolved to: {hostname}")
                except:
                    print(f"  -> Could not resolve {packet['dst_ip']}")
                
            except queue.Empty:
                continue
        
        print(f"\nCaptured {packet_count} packets in 30 seconds")
        
        if packet_count > 0:
            print("✅ Real traffic capture is working!")
        else:
            print("❌ No packets captured - may need root privileges")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        print("This usually means you need to run with sudo:")
        print("sudo python3 simple_real_traffic.py")

if __name__ == "__main__":
    main()


