import os
import time
import threading
import socket
import datetime
import json
import csv
import psutil
import numpy as np
from collections import defaultdict, deque
import subprocess
import platform
from scapy.all import sniff, IP, TCP, UDP, ICMP
from flask import Flask, jsonify, render_template, send_from_directory
from flask_socketio import SocketIO
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ddos_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DDoS-Detector")

# Create Flask app
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Create data directory if it doesn't exist
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Global variables
ATTACK_THRESHOLD = 0.75  # Confidence threshold for attack detection
PACKET_WINDOW = 100      # Number of packets to analyze at once
MAX_HISTORY = 300        # Maximum traffic history points

# Traffic statistics
traffic_stats = {
    'total_packets': 0,
    'syn_packets': 0,
    'udp_packets': 0,
    'icmp_packets': 0,
    'http_packets': 0,
    'https_packets': 0,
    'suspicious_ips': set(),
    'blocked_ips': set()
}

# Traffic history for charts
traffic_history = {
    'timestamps': deque(maxlen=MAX_HISTORY),
    'normal': deque(maxlen=MAX_HISTORY),
    'attack': deque(maxlen=MAX_HISTORY)
}

# IP statistics tracking
ip_stats = defaultdict(lambda: {
    'packet_count': 0,
    'syn_count': 0,
    'last_seen': 0,
    'ports_targeted': set(),
    'packet_sizes': [],
    'is_blocked': False
})

# Attack log
attack_log = []

class DDoSDetector:
    def __init__(self):
        self.threshold = ATTACK_THRESHOLD
        self.window_size = PACKET_WINDOW
        self.packet_buffer = []
        self.baseline_established = False
        self.baseline_stats = {
            'avg_packet_rate': 0,
            'avg_syn_rate': 0,
            'avg_udp_rate': 0,
            'avg_icmp_rate': 0
        }
        self.attack_types = {
            'syn_flood': self.detect_syn_flood,
            'udp_flood': self.detect_udp_flood,
            'icmp_flood': self.detect_icmp_flood,
            'http_flood': self.detect_http_flood,
            'port_scan': self.detect_port_scan
        }
        
    def process_packet(self, packet):
        # Extract packet features
        if IP in packet:
            features = self.extract_features(packet)
            
            # Add to global traffic stats
            traffic_stats['total_packets'] += 1
            
            # Update protocol specific counters
            if TCP in packet:
                if packet[TCP].flags & 0x02:  # SYN flag
                    traffic_stats['syn_packets'] += 1
                    ip_stats[features['src_ip']]['syn_count'] += 1
                if features.get('dst_port') == 80:
                    traffic_stats['http_packets'] += 1
                if features.get('dst_port') == 443:
                    traffic_stats['https_packets'] += 1
            elif UDP in packet:
                traffic_stats['udp_packets'] += 1
            elif ICMP in packet:
                traffic_stats['icmp_packets'] += 1
                
            # Update IP statistics
            src_ip = features['src_ip']
            ip_stats[src_ip]['packet_count'] += 1
            ip_stats[src_ip]['last_seen'] = time.time()
            if 'dst_port' in features:
                ip_stats[src_ip]['ports_targeted'].add(features['dst_port'])
            if 'packet_size' in features:
                ip_stats[src_ip]['packet_sizes'].append(features['packet_size'])
                
            # Add to packet buffer for analysis
            self.packet_buffer.append(features)
            
            # Check if we have enough packets to analyze
            if len(self.packet_buffer) >= self.window_size:
                # Establish baseline if not already done
                if not self.baseline_established and traffic_stats['total_packets'] > self.window_size * 3:
                    self.establish_baseline()
                
                # Detect attacks
                attack_detected, attack_type, confidence, source_ip = self.detect_attack()
                
                if attack_detected:
                    self.handle_attack(attack_type, confidence, source_ip)
                    
                # Clear buffer
                self.packet_buffer = []
            
            # Update traffic history for charts
            self.update_traffic_history()
    
    def extract_features(self, packet):
        """Extract relevant features from packet"""
        features = {
            'timestamp': time.time(),
            'packet_size': len(packet),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto
        }
        
        if TCP in packet:
            features.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags
            })
        elif UDP in packet:
            features.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        elif ICMP in packet:
            features.update({
                'icmp_type': packet[ICMP].type,
                'icmp_code': packet[ICMP].code
            })
            
        return features
    
    def establish_baseline(self):
        """Establish baseline traffic patterns"""
        logger.info("Establishing baseline traffic patterns")
        
        # Calculate average packet rates
        total_time = self.packet_buffer[-1]['timestamp'] - self.packet_buffer[0]['timestamp']
        if total_time > 0:
            self.baseline_stats['avg_packet_rate'] = len(self.packet_buffer) / total_time
            self.baseline_stats['avg_syn_rate'] = traffic_stats['syn_packets'] / total_time
            self.baseline_stats['avg_udp_rate'] = traffic_stats['udp_packets'] / total_time
            self.baseline_stats['avg_icmp_rate'] = traffic_stats['icmp_packets'] / total_time
            
        self.baseline_established = True
        logger.info(f"Baseline established: {self.baseline_stats}")
        
    def detect_attack(self):
        """Analyze packet buffer for attack patterns"""
        max_confidence = 0
        attack_type = None
        source_ip = None
        
        # Check each attack type
        for name, detector in self.attack_types.items():
            confidence, ip = detector()
            if confidence > max_confidence:
                max_confidence = confidence
                attack_type = name
                source_ip = ip
        
        # Return attack details if confidence exceeds threshold
        if max_confidence > self.threshold:
            return True, attack_type, max_confidence, source_ip
        return False, None, 0, None
        
    def detect_syn_flood(self):
        """Detect SYN flood attacks"""
        if not self.baseline_established:
            return 0, None
            
        # Count SYN packets
        syn_packets = [p for p in self.packet_buffer if 'flags' in p and p['flags'] & 0x02]
        
        if not syn_packets:
            return 0, None
            
        # Calculate rate
        total_time = self.packet_buffer[-1]['timestamp'] - self.packet_buffer[0]['timestamp']
        if total_time <= 0:
            return 0, None
            
        current_syn_rate = len(syn_packets) / total_time
        
        # Calculate confidence based on deviation from baseline
        if self.baseline_stats['avg_syn_rate'] > 0:
            confidence = min(1.0, (current_syn_rate / self.baseline_stats['avg_syn_rate'] - 1) / 10)
        else:
            confidence = 0.5 if current_syn_rate > 10 else 0
        
        # Find most likely source IP
        if confidence > 0:
            src_ips = [p['src_ip'] for p in syn_packets]
            if src_ips:
                most_common_ip = max(set(src_ips), key=src_ips.count)
                ip_ratio = src_ips.count(most_common_ip) / len(src_ips)
                
                if ip_ratio > 0.5:  # If more than 50% from same IP
                    return confidence * ip_ratio, most_common_ip
        
        return confidence, None
        
    def detect_udp_flood(self):
        """Detect UDP flood attacks"""
        if not self.baseline_established:
            return 0, None
            
        # Count UDP packets
        udp_packets = [p for p in self.packet_buffer if p['protocol'] == 17]  # UDP protocol
        
        if not udp_packets:
            return 0, None
            
        # Calculate rate
        total_time = self.packet_buffer[-1]['timestamp'] - self.packet_buffer[0]['timestamp']
        if total_time <= 0:
            return 0, None
            
        current_udp_rate = len(udp_packets) / total_time
        
        # Calculate confidence based on deviation from baseline
        if self.baseline_stats['avg_udp_rate'] > 0:
            confidence = min(1.0, (current_udp_rate / self.baseline_stats['avg_udp_rate'] - 1) / 10)
        else:
            confidence = 0.5 if current_udp_rate > 10 else 0
        
        # Find most likely source IP
        if confidence > 0:
            src_ips = [p['src_ip'] for p in udp_packets]
            if src_ips:
                most_common_ip = max(set(src_ips), key=src_ips.count)
                ip_ratio = src_ips.count(most_common_ip) / len(src_ips)
                
                if ip_ratio > 0.5:  # If more than 50% from same IP
                    return confidence * ip_ratio, most_common_ip
        
        return confidence, None
        
    def detect_icmp_flood(self):
        """Detect ICMP flood attacks"""
        if not self.baseline_established:
            return 0, None
            
        # Count ICMP packets
        icmp_packets = [p for p in self.packet_buffer if p['protocol'] == 1]  # ICMP protocol
        
        if not icmp_packets:
            return 0, None
            
        # Calculate rate
        total_time = self.packet_buffer[-1]['timestamp'] - self.packet_buffer[0]['timestamp']
        if total_time <= 0:
            return 0, None
            
        current_icmp_rate = len(icmp_packets) / total_time
        
        # Calculate confidence based on deviation from baseline
        if self.baseline_stats['avg_icmp_rate'] > 0:
            confidence = min(1.0, (current_icmp_rate / self.baseline_stats['avg_icmp_rate'] - 1) / 5)
        else:
            confidence = 0.5 if current_icmp_rate > 5 else 0
        
        # Find most likely source IP
        if confidence > 0:
            src_ips = [p['src_ip'] for p in icmp_packets]
            if src_ips:
                most_common_ip = max(set(src_ips), key=src_ips.count)
                ip_ratio = src_ips.count(most_common_ip) / len(src_ips)
                
                if ip_ratio > 0.5:  # If more than 50% from same IP
                    return confidence * ip_ratio, most_common_ip
        
        return confidence, None
        
    def detect_http_flood(self):
        """Detect HTTP/HTTPS flood attacks"""
        http_packets = [p for p in self.packet_buffer if 'dst_port' in p and p['dst_port'] in (80, 443)]
        
        if not http_packets:
            return 0, None
            
        # Calculate rate
        total_time = self.packet_buffer[-1]['timestamp'] - self.packet_buffer[0]['timestamp']
        if total_time <= 0:
            return 0, None
            
        current_http_rate = len(http_packets) / total_time
        
        # Basic threshold for HTTP flood
        confidence = 0.5 if current_http_rate > 20 else 0
        
        # Find most likely source IP
        if confidence > 0:
            src_ips = [p['src_ip'] for p in http_packets]
            if src_ips:
                most_common_ip = max(set(src_ips), key=src_ips.count)
                ip_ratio = src_ips.count(most_common_ip) / len(src_ips)
                
                if ip_ratio > 0.5:  # If more than 50% from same IP
                    return confidence * ip_ratio, most_common_ip
        
        return confidence, None
        
    def detect_port_scan(self):
        """Detect port scanning"""
        # Group packets by source IP
        src_ip_packets = defaultdict(list)
        for p in self.packet_buffer:
            if 'dst_port' in p:
                src_ip_packets[p['src_ip']].append(p)
        
        max_confidence = 0
        max_ip = None
        
        # Check each source IP
        for ip, packets in src_ip_packets.items():
            if len(packets) < 5:
                continue
                
            # Count unique destination ports
            dst_ports = set(p['dst_port'] for p in packets)
            
            # If targeting many ports, likely a scan
            if len(dst_ports) > 10:
                port_ratio = len(dst_ports) / len(packets)
                confidence = min(1.0, port_ratio * len(dst_ports) / 50)
                
                if confidence > max_confidence:
                    max_confidence = confidence
                    max_ip = ip
        
        return max_confidence, max_ip
    
    def handle_attack(self, attack_type, confidence, source_ip):
        """Handle detected attack"""
        # Log attack
        attack_data = {
            'timestamp': time.time(),
            'type': attack_type,
            'confidence': confidence,
            'source_ip': source_ip
        }
        
        logger.warning(f"Attack detected: {attack_type} from {source_ip} (confidence: {confidence:.2f})")
        
        # Add IP to suspicious list
        if source_ip:
            traffic_stats['suspicious_ips'].add(source_ip)
            
            # Block IP if highly confident
            if confidence > 0.9 and source_ip not in traffic_stats['blocked_ips']:
                traffic_stats['blocked_ips'].add(source_ip)
                self.block_ip(source_ip)
        
        # Add to attack log
        attack_log.append(attack_data)
        
        # Only keep the latest 100 attacks in memory
        if len(attack_log) > 100:
            attack_log.pop(0)
        
        # Save attack to log file
        self.log_attack(attack_data)
        
        # Notify frontend
        try:
            socketio.emit('attack_detected', attack_data)
        except Exception as e:
            logger.error(f"Failed to emit attack event: {e}")
    
    def log_attack(self, attack_data):
        """Save attack details to log file"""
        try:
            log_file = os.path.join('logs', 'attacks.csv')
            file_exists = os.path.isfile(log_file)
            
            with open(log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['timestamp', 'type', 'confidence', 'source_ip'])
                
                writer.writerow([
                    datetime.datetime.fromtimestamp(attack_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                    attack_data['type'],
                    attack_data['confidence'],
                    attack_data['source_ip']
                ])
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
    
    def block_ip(self, ip):
        """Block an IP address using firewall"""
        logger.info(f"Blocking IP: {ip}")
        
        if platform.system() == "Windows":
            try:
                # Windows firewall command
                cmd = f'netsh advfirewall firewall add rule name="DDoS_Blocked_{ip}" dir=in action=block remoteip={ip}'
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                logger.error(f"Failed to block IP {ip}: {e}")
        else:
            try:
                # Linux iptables command
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
                subprocess.Popen(cmd, shell=True)
            except Exception as e:
                logger.error(f"Failed to block IP {ip}: {e}")
    
    def update_traffic_history(self):
        """Update traffic history for charts"""
        now = time.time()
        traffic_history['timestamps'].append(now)
        
        # Calculate normal vs attack traffic
        attack_traffic = sum(1 for ip in traffic_stats['suspicious_ips'] 
                            if ip_stats[ip]['last_seen'] > now - 60)
        normal_traffic = traffic_stats['total_packets'] - attack_traffic
        
        traffic_history['normal'].append(normal_traffic)
        traffic_history['attack'].append(attack_traffic)

def system_monitor():
    """Monitor system resources"""
    while True:
        try:
            # Get system stats
            cpu_usage = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            network_io = psutil.net_io_counters()
            
            system_stats = {
                'timestamp': time.time(),
                'cpu_usage': cpu_usage,
                'memory_usage': memory.percent,
                'memory_available': memory.available / (1024 * 1024),  # MB
                'memory_total': memory.total / (1024 * 1024),  # MB
                'network_in': network_io.bytes_recv,
                'network_out': network_io.bytes_sent
            }
            
            # Emit to frontend
            socketio.emit('system_update', system_stats)
            
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error in system monitor: {e}")
            time.sleep(5)

def packet_callback(packet):
    """Callback for packet sniffing"""
    try:
        detector.process_packet(packet)
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def get_network_interfaces():
    """Get list of available network interfaces"""
    try:
        interfaces = []
        if platform.system() == "Windows":
            # On Windows, use ipconfig
            output = subprocess.check_output("ipconfig", shell=True).decode('utf-8', errors='ignore')
            for line in output.split('\n'):
                if "adapter" in line.lower():
                    interfaces.append(line.strip(':'))
        else:
            # On Unix-like systems, use ifconfig
            output = subprocess.check_output("ifconfig", shell=True).decode('utf-8', errors='ignore')
            current = None
            for line in output.split('\n'):
                if line and not line.startswith(' '):
                    current = line.split(':')[0]
                    interfaces.append(current)
        
        return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return ["eth0", "wlan0"]  # Default fallback

@app.route('/')
def index():
    """Serve the dashboard HTML"""
    return send_from_directory('.', 'index.html')

@app.route('/api/stats')
def get_stats():
    """Get current stats"""
    # Convert sets to lists for JSON serialization
    suspicious_ips = list(traffic_stats['suspicious_ips'])
    blocked_ips = list(traffic_stats['blocked_ips'])
    
    return jsonify({
        'traffic_stats': {
            'total_packets': traffic_stats['total_packets'],
            'syn_packets': traffic_stats['syn_packets'],
            'udp_packets': traffic_stats['udp_packets'],
            'icmp_packets': traffic_stats['icmp_packets'],
            'http_packets': traffic_stats['http_packets'],
            'https_packets': traffic_stats['https_packets'],
            'suspicious_ips': suspicious_ips,
            'blocked_ips': blocked_ips
        },
        'traffic_history': {
            'timestamps': list(traffic_history['timestamps']),
            'normal': list(traffic_history['normal']),
            'attack': list(traffic_history['attack'])
        },
        'attack_log': attack_log[-10:]  # Return last 10 attacks
    })

@app.route('/api/interfaces')
def get_interfaces():
    """Get available network interfaces"""
    return jsonify(get_network_interfaces())

if __name__ == '__main__':
    logger.info("Starting DDoS Detection System...")
    
    # Create detector
    detector = DDoSDetector()
    
    try:
        # Get network interfaces
        interfaces = get_network_interfaces()
        logger.info(f"Available network interfaces: {interfaces}")
        
        # Start packet capture in separate thread
        logger.info("Starting packet capture...")
        capture_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=0))
        capture_thread.daemon = True
        capture_thread.start()
        
        # Start system monitoring
        logger.info("Starting system monitoring...")
        monitor_thread = threading.Thread(target=system_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start Flask server
        logger.info("Starting web server on port 5000...")
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Error: {e}") 