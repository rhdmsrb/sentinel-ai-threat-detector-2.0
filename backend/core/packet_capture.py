# File: core/packet_capture.py

import asyncio
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from typing import Dict, Optional, Callable
import logging

logger = logging.getLogger(__name__)

class PacketCapture:
    """Improved real-time packet capture with proper threading"""
    
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.is_running = False
        self.packet_count = 0
        self.capture_thread = None
        self.packet_callback = None
        self.session_id = None
        
    def extract_packet_features(self, packet) -> Optional[Dict]:
        """Extract features from packet"""
        try:
            if not packet.haslayer(IP):
                return None
            
            features = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'packet_length': len(packet),
                'ttl': packet[IP].ttl,
                'flags': 0,
            }
            
            if packet.haslayer(TCP):
                features.update({
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'tcp_flags': int(packet[TCP].flags),
                    'tcp_window': packet[TCP].window,
                    'protocol_type': 'TCP',
                    'flags': int(packet[TCP].flags)
                })
            elif packet.haslayer(UDP):
                features.update({
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport,
                    'protocol_type': 'UDP'
                })
            elif packet.haslayer(ICMP):
                features.update({
                    'icmp_type': packet[ICMP].type,
                    'icmp_code': packet[ICMP].code,
                    'protocol_type': 'ICMP'
                })
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def _packet_handler(self, packet):
        """Internal packet handler"""
        if not self.is_running:
            return
        
        features = self.extract_packet_features(packet)
        if features and self.packet_callback:
            try:
                self.packet_callback(features)
                self.packet_count += 1
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")
    
    def _capture_loop(self):
        """Main capture loop running in separate thread"""
        logger.info(f"Starting packet capture on {self.interface}")
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            logger.info(f"Capture stopped. Total packets: {self.packet_count}")
    
    def start(self, callback: Callable):
        """Start packet capture in background thread"""
        if self.is_running:
            logger.warning("Capture already running")
            return False
        
        self.packet_callback = callback
        self.is_running = True
        self.packet_count = 0
        
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self.capture_thread.start()
        
        logger.info("Packet capture started")
        return True
    
    def stop(self):
        """Stop packet capture"""
        if not self.is_running:
            logger.warning("Capture not running")
            return False
        
        self.is_running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        logger.info(f"Capture stopped. Total packets: {self.packet_count}")
        return True
    
    def get_stats(self) -> Dict:
        """Get capture statistics"""
        return {
            'is_running': self.is_running,
            'packet_count': self.packet_count,
            'interface': self.interface
        }
