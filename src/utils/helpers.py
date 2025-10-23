"""
Helper utility functions
"""

import hashlib
import time
import re
from typing import Optional

def format_timestamp(timestamp: float) -> str:
    """Format timestamp to readable string"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

def calculate_hash(data: str) -> str:
    """Calculate SHA-256 hash of data"""
    return hashlib.sha256(data.encode()).hexdigest()

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))

def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    if not validate_ip_address(ip):
        return False
    
    parts = ip.split('.')
    first_octet = int(parts[0])
    
    # Private IP ranges
    if first_octet == 10:
        return True
    elif first_octet == 172 and 16 <= int(parts[1]) <= 31:
        return True
    elif first_octet == 192 and int(parts[1]) == 168:
        return True
    
    return False

def normalize_port(port: Optional[int]) -> int:
    """Normalize port number"""
    if port is None:
        return 0
    return max(0, min(65535, port))

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for count in char_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy
