import os
import time
import threading
import random
import datetime
import json
import csv
import psutil
import numpy as np
from collections import defaultdict, deque
import subprocess
import platform
import socket
from flask import Flask, jsonify, send_from_directory
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
SIMULATION_MODE = True   # Run in simulation mode

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

# Protocols
TCP = 6
UDP = 17
ICMP = 1

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
        # Add to global traffic stats
        traffic_stats['total_packets'] += 1
        
        # Update protocol specific counters
        if packet['protocol'] == TCP:
            if packet.get('flags') & 0x02:  # SYN flag
                traffic_stats['syn_packets'] += 1
                ip_stats[packet['src_ip']]['syn_count'] += 1
            if packet.get('dst_port') == 80:
                traffic_stats['http_packets'] += 1
            if packet.get('dst_port') == 443:
                traffic_stats['https_packets'] += 1
        elif packet['protocol'] == UDP:
            traffic_stats['udp_packets'] += 1
        elif packet['protocol'] == ICMP:
            traffic_stats['icmp_packets'] += 1
            
        # Update IP statistics
        src_ip = packet['src_ip']
        ip_stats[src_ip]['packet_count'] += 1
        ip_stats[src_ip]['last_seen'] = time.time()
        if 'dst_port' in packet:
            ip_stats[src_ip]['ports_targeted'].add(packet['dst_port'])
        if 'packet_size' in packet:
            ip_stats[src_ip]['packet_sizes'].append(packet['packet_size'])
            
        # Add to packet buffer for analysis
        self.packet_buffer.append(packet)
        
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
        syn_packets = [p for p in self.packet_buffer if p['protocol'] == TCP and p.get('flags', 0) & 0x02]
        
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
        udp_packets = [p for p in self.packet_buffer if p['protocol'] == UDP]
        
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
        icmp_packets = [p for p in self.packet_buffer if p['protocol'] == ICMP]
        
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
        http_packets = [p for p in self.packet_buffer if p['protocol'] == TCP and p.get('dst_port') in (80, 443)]
        
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

def generate_random_packet():
    """Generate a random packet for simulation"""
    # Random source IP and destination IP
    src_ip = f"192.168.1.{random.randint(1, 254)}"
    dst_ip = f"192.168.1.{random.randint(1, 254)}"
    
    # Random packet size
    packet_size = random.randint(40, 1500)
    
    # Random protocol (TCP, UDP, ICMP)
    protocol = random.choices([TCP, UDP, ICMP], weights=[0.7, 0.2, 0.1])[0]
    
    # Basic packet
    packet = {
        'timestamp': time.time(),
        'packet_size': packet_size,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol
    }
    
    # Additional protocol-specific fields
    if protocol == TCP:
        packet['src_port'] = random.randint(1024, 65535)
        packet['dst_port'] = random.choices([80, 443, 22, 21, 25] + list(range(1024, 10000)), 
                                         weights=[0.3, 0.3, 0.1, 0.05, 0.05] + [0.2/8976] * 8976)[0]
        packet['flags'] = random.randint(0, 63)  # 6 bits for TCP flags
    elif protocol == UDP:
        packet['src_port'] = random.randint(1024, 65535)
        packet['dst_port'] = random.choices([53, 123, 161, 67, 68] + list(range(1024, 10000)),
                                         weights=[0.2, 0.1, 0.1, 0.05, 0.05] + [0.5/8976] * 8976)[0]
    elif protocol == ICMP:
        packet['icmp_type'] = random.randint(0, 255)
        packet['icmp_code'] = random.randint(0, 255)
    
    return packet

def simulate_attack():
    """Periodically generate attack traffic"""
    while True:
        # Sleep between 10-60 seconds between attacks
        time.sleep(random.randint(10, 60))
        
        # Select attack type
        attack_type = random.choice(['syn_flood', 'udp_flood', 'icmp_flood', 'http_flood', 'port_scan'])
        
        # Attack source
        attacker_ip = f"192.168.1.{random.randint(1, 254)}"
        target_ip = f"192.168.1.{random.randint(1, 254)}"
        
        logger.info(f"Simulating {attack_type} attack from {attacker_ip}")
        
        # Generate attack packets
        attack_duration = random.randint(3, 10)  # seconds
        attack_end = time.time() + attack_duration
        
        attack_thread = threading.Thread(target=generate_attack_packets, 
                                          args=(attack_type, attacker_ip, target_ip, attack_end))
        attack_thread.daemon = True
        attack_thread.start()

def generate_attack_packets(attack_type, attacker_ip, target_ip, end_time):
    """Generate packets for a specific attack type"""
    while time.time() < end_time:
        if attack_type == 'syn_flood':
            packet = {
                'timestamp': time.time(),
                'packet_size': random.randint(40, 60),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'protocol': TCP,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 8080, 8443]),
                'flags': 0x02  # SYN flag
            }
        elif attack_type == 'udp_flood':
            packet = {
                'timestamp': time.time(),
                'packet_size': random.randint(40, 1500),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'protocol': UDP,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.randint(1, 65535)
            }
        elif attack_type == 'icmp_flood':
            packet = {
                'timestamp': time.time(),
                'packet_size': random.randint(56, 84),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'protocol': ICMP,
                'icmp_type': 8,  # Echo request
                'icmp_code': 0
            }
        elif attack_type == 'http_flood':
            packet = {
                'timestamp': time.time(),
                'packet_size': random.randint(200, 1500),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'protocol': TCP,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443]),
                'flags': random.choice([0x02, 0x10, 0x18])  # SYN, ACK, or PUSH+ACK
            }
        elif attack_type == 'port_scan':
            packet = {
                'timestamp': time.time(),
                'packet_size': random.randint(40, 60),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'protocol': TCP,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.randint(1, 65535),
                'flags': 0x02  # SYN flag
            }
        
        # Process the packet
        detector.process_packet(packet)
        
        # Add some delay between packets (very fast attacks)
        time.sleep(0.01)

def simulation_thread():
    """Run the simulation thread"""
    logger.info("Starting simulation mode")
    
    # Normal traffic generation
    while True:
        # Generate normal traffic at a slower rate
        time.sleep(0.1)  # 10 packets per second
        packet = generate_random_packet()
        detector.process_packet(packet)

@app.route('/')
def index():
    """Serve the dashboard HTML directly"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AI DDoS Defense System</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.socket.io/4.6.1/socket.io.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body class="bg-gray-900 text-white p-4">
        <h1 class="text-2xl font-bold mb-4">AI DDoS Defense System</h1>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div class="bg-gray-800 p-4 rounded">
                <h2 class="text-xl mb-2">System Status</h2>
                <div class="mb-2">
                    <div class="flex justify-between">
                        <span>CPU Usage</span>
                        <span id="cpuUsage">0%</span>
                    </div>
                    <div class="w-full bg-gray-700 h-2 rounded">
                        <div id="cpuBar" class="bg-blue-500 h-2 rounded" style="width: 0%"></div>
                    </div>
                </div>
                <div class="mb-2">
                    <div class="flex justify-between">
                        <span>Memory Usage</span>
                        <span id="memoryUsage">0%</span>
                    </div>
                    <div class="w-full bg-gray-700 h-2 rounded">
                        <div id="memoryBar" class="bg-green-500 h-2 rounded" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            
            <div class="bg-gray-800 p-4 rounded">
                <h2 class="text-xl mb-2">Traffic Stats</h2>
                <div class="grid grid-cols-2 gap-2">
                    <div class="bg-gray-700 p-2 rounded">
                        <div class="text-sm text-gray-400">Total Packets</div>
                        <div id="total-packets" class="text-xl">0</div>
                    </div>
                    <div class="bg-gray-700 p-2 rounded">
                        <div class="text-sm text-gray-400">Suspicious IPs</div>
                        <div id="suspicious-ips" class="text-xl text-yellow-400">0</div>
                    </div>
                    <div class="bg-gray-700 p-2 rounded">
                        <div class="text-sm text-gray-400">Blocked IPs</div>
                        <div id="blocked-ips" class="text-xl text-red-400">0</div>
                    </div>
                    <div class="bg-gray-700 p-2 rounded">
                        <div class="text-sm text-gray-400">Detection Rate</div>
                        <div id="detection-rate" class="text-xl text-green-400">0%</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="bg-gray-800 p-4 rounded mb-4">
            <h2 class="text-xl mb-2">Traffic Visualization</h2>
            <div class="h-64">
                <canvas id="trafficChart"></canvas>
            </div>
        </div>
        
        <div class="bg-gray-800 p-4 rounded">
            <h2 class="text-xl mb-2">Attack Log</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-gray-700">
                            <th class="text-left p-2">Time</th>
                            <th class="text-left p-2">Source IP</th>
                            <th class="text-left p-2">Type</th>
                            <th class="text-right p-2">Confidence</th>
                        </tr>
                    </thead>
                    <tbody id="attackTable">
                        <!-- Will be populated dynamically -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Connect to socket.io
                const socket = io();
                
                // Set up charts
                const ctx = document.getElementById('trafficChart').getContext('2d');
                const trafficChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: Array(30).fill(''),
                        datasets: [
                            {
                                label: 'Normal Traffic',
                                borderColor: 'rgba(72, 187, 120, 1)',
                                backgroundColor: 'rgba(72, 187, 120, 0.2)',
                                data: Array(30).fill(0),
                                fill: true
                            },
                            {
                                label: 'Attack Traffic',
                                borderColor: 'rgba(239, 68, 68, 1)',
                                backgroundColor: 'rgba(239, 68, 68, 0.2)',
                                data: Array(30).fill(0),
                                fill: true
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
                
                // Handle system updates
                socket.on('system_update', function(data) {
                    document.getElementById('cpuUsage').textContent = data.cpu_usage.toFixed(1) + '%';
                    document.getElementById('cpuBar').style.width = data.cpu_usage + '%';
                    
                    document.getElementById('memoryUsage').textContent = data.memory_usage.toFixed(1) + '%';
                    document.getElementById('memoryBar').style.width = data.memory_usage + '%';
                });
                
                // Handle attack detection
                socket.on('attack_detected', function(data) {
                    // Add to attack table
                    addAttackToTable(data);
                });
                
                function addAttackToTable(attack) {
                    const table = document.getElementById('attackTable');
                    const row = document.createElement('tr');
                    row.className = 'border-b border-gray-700';
                    
                    // Format timestamp
                    const date = new Date(attack.timestamp * 1000);
                    const timestamp = date.getHours() + ':' + 
                                     date.getMinutes().toString().padStart(2, '0') + ':' +
                                     date.getSeconds().toString().padStart(2, '0');
                    
                    row.innerHTML = `
                        <td class="p-2">${timestamp}</td>
                        <td class="p-2">${attack.source_ip}</td>
                        <td class="p-2">${attack.type.replace('_', ' ')}</td>
                        <td class="p-2 text-right">${(attack.confidence * 100).toFixed(1)}%</td>
                    `;
                    
                    if (table.firstChild) {
                        table.insertBefore(row, table.firstChild);
                    } else {
                        table.appendChild(row);
                    }
                }
                
                // Fetch stats every 5 seconds
                function fetchStats() {
                    fetch('/api/stats')
                        .then(response => response.json())
                        .then(data => {
                            // Update traffic stats
                            document.getElementById('total-packets').textContent = 
                                data.traffic_stats.total_packets;
                            document.getElementById('suspicious-ips').textContent = 
                                data.traffic_stats.suspicious_ips.length;
                            document.getElementById('blocked-ips').textContent = 
                                data.traffic_stats.blocked_ips.length;
                            
                            // Update detection rate (simulated)
                            const accuracy = Math.floor(85 + Math.random() * 10);
                            document.getElementById('detection-rate').textContent = accuracy + '%';
                            
                            // Update chart
                            if (data.traffic_history.timestamps.length > 0) {
                                // Convert timestamps to labels
                                const labels = data.traffic_history.timestamps.map(ts => {
                                    const date = new Date(ts * 1000);
                                    return date.getHours() + ':' + 
                                           date.getMinutes().toString().padStart(2, '0');
                                });
                                
                                trafficChart.data.labels = labels;
                                trafficChart.data.datasets[0].data = data.traffic_history.normal;
                                trafficChart.data.datasets[1].data = data.traffic_history.attack;
                                trafficChart.update();
                            }
                            
                            // Populate attack table
                            const table = document.getElementById('attackTable');
                            table.innerHTML = '';
                            
                            data.attack_log.forEach(attack => {
                                addAttackToTable(attack);
                            });
                        })
                        .catch(error => {
                            console.error('Error fetching stats:', error);
                        });
                }
                
                // Initial fetch
                fetchStats();
                
                // Update every 5 seconds
                setInterval(fetchStats, 5000);
            });
        </script>
    </body>
    </html>
    """
    return html

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

if __name__ == '__main__':
    logger.info("Starting DDoS Detection System (Simulation Mode)...")
    
    # Create detector
    detector = DDoSDetector()
    
    try:
        # Start system monitoring
        logger.info("Starting system monitoring...")
        monitor_thread = threading.Thread(target=system_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        if SIMULATION_MODE:
            # Start simulation threads
            sim_thread = threading.Thread(target=simulation_thread)
            sim_thread.daemon = True
            sim_thread.start()
            
            # Start attack simulation
            attack_sim_thread = threading.Thread(target=simulate_attack)
            attack_sim_thread.daemon = True
            attack_sim_thread.start()
        
        # Start Flask server
        logger.info("Starting web server on port 5000...")
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Error: {e}") 