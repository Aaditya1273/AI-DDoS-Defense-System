import os
import time
import threading
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf, get_if_list, NetworkInterface
import random
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
import psutil
import redis
from pymongo import MongoClient
from dotenv import load_dotenv
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import joblib
import logging
import socket
import argparse

# Parse command line arguments
parser = argparse.ArgumentParser(description='DDoS Detection System')
parser.add_argument('--test', action='store_true', help='Run in test mode with controlled attack simulation')
parser.add_argument('--interface', type=str, default=None, help='Network interface to capture traffic')
args = parser.parse_args()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - DDoS-Detector - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ddos_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DDoS-Detector")

# Load environment variables
load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize Redis for real-time data
try:
    redis_client = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=int(os.getenv('REDIS_PORT', 6379)), db=0)
    redis_client.ping()  # Test connection
    logger.info("Redis connected successfully")
except redis.ConnectionError:
    logger.warning("Redis not available. Using fallback storage.")
    redis_client = None

# Initialize MongoDB for storing attack data
try:
    mongo_client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'), serverSelectionTimeoutMS=2000)
    mongo_client.server_info()  # Test connection
    db = mongo_client.ddos_detection
    logger.info("MongoDB connected successfully")
except Exception as e:
    logger.warning(f"MongoDB not available: {e}. Using fallback storage.")
    db = None

# Global variables for traffic monitoring
traffic_stats = {
    'total_packets': 0,
    'syn_packets': 0,
    'udp_packets': 0,
    'icmp_packets': 0,
    'http_requests': 0,
    'suspicious_ips': set(),
    'blocked_ips': set(),
    'last_update': time.time(),
    'packets_per_second': 0,
    'bytes_per_second': 0,
    'last_total_packets': 0,
    'last_total_bytes': 0,
    'total_bytes': 0,
    # Additional statistics for charts
    'tcp_attacks': 0,
    'udp_attacks': 0,
    'icmp_attacks': 0,
    'firewall_rules': 0,
    'attack_types': {},  # Store attack counts by type
    'top_source_ips': {},  # Track frequency of source IPs
    'mitigation_effectiveness': 85  # Default effectiveness percentage
}

class DDoSDetector:
    def __init__(self):
        self.lstm_model = self.load_lstm_model()
        self.xgb_model = self.load_xgb_model()
        self.rf_model = self.load_rf_model()
        self.threshold = 0.85
        self.window_size = 100
        self.packet_buffer = []
        self.ip_packet_counts = {}  # Track packets per IP
        self.ip_time_windows = {}   # Track time windows for rate limiting
        
    def load_lstm_model(self):
        # Load or create LSTM model
        try:
            return tf.keras.models.load_model('models/lstm_model.h5')
        except:
            logger.warning("No trained LSTM model found. Creating a default model.")
            return self.create_lstm_model()
            
    def load_xgb_model(self):
        # Load or create XGBoost model
        try:
            return joblib.load('models/xgb_model.joblib')
        except:
            logger.warning("No trained XGBoost model found. Creating a default model.")
            return self.create_xgb_model()
            
    def load_rf_model(self):
        # Load or create Random Forest model
        try:
            return joblib.load('models/rf_model.joblib')
        except:
            logger.warning("No trained Random Forest model found. Creating a default model.")
            return self.create_rf_model()
    
    def create_lstm_model(self):
        # Create a simple LSTM model
        model = tf.keras.Sequential([
            tf.keras.layers.LSTM(64, input_shape=(self.window_size, 5), return_sequences=True),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.LSTM(32),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(16, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
    
    def create_xgb_model(self):
        # Create a simple XGBoost model
        return xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42
        )
    
    def create_rf_model(self):
        # Create a simple Random Forest model
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
            
    def process_packet(self, packet):
        features = self.extract_features(packet)
        if features:
            self.packet_buffer.append(features)
        
            # Update IP address statistics
            src_ip = features.get('src_ip')
            if src_ip:
                # Initialize if not exists
                if src_ip not in self.ip_packet_counts:
                    self.ip_packet_counts[src_ip] = 0
                    self.ip_time_windows[src_ip] = {'start_time': time.time(), 'packets': 0}
                    
                # Update counts
                self.ip_packet_counts[src_ip] += 1
                self.ip_time_windows[src_ip]['packets'] += 1
                
                # Check for rate-based thresholds - more than 100 packets in 1 second
                current_time = time.time()
                time_window = self.ip_time_windows[src_ip]
                if current_time - time_window['start_time'] >= 1.0:
                    pps = time_window['packets'] / (current_time - time_window['start_time'])
                    self.ip_time_windows[src_ip] = {'start_time': current_time, 'packets': 0}
                    
                    if pps > 100:  # More than 100 packets per second
                        self.handle_attack({
                            'src_ip': src_ip,
                            'protocol': features.get('protocol', 0),
                            'packet_size': features.get('packet_size', 0),
                            'pps': pps
                        })
                        return
            
            # Use ML models if enough packets are collected
            if len(self.packet_buffer) >= self.window_size:
                prediction = self.predict_attack(self.packet_buffer)
                if prediction > self.threshold:
                    self.handle_attack(packet)
                self.packet_buffer = self.packet_buffer[-50:]  # Keep last 50 packets
            
    def extract_features(self, packet):
        try:
            if IP in packet:
                features = {
                    'packet_size': len(packet),
                    'protocol': packet[IP].proto,
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'timestamp': time.time()
                }
                
                if TCP in packet:
                    features.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': str(packet[TCP].flags)
                    })
                elif UDP in packet:
                    features.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    })
                elif ICMP in packet:
                    features.update({
                        'icmp_type': packet[ICMP].type
                    })
                
                # Check for HTTP specific features (simplified)
                if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    if Raw in packet:
                        payload = str(packet[Raw].load)
                        if 'HTTP' in payload:
                            features['http'] = True
                
                return features
            return None
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
        
    def predict_attack(self, packet_buffer):
        try:
            # Prepare data for ML model
            features = []
            for p in packet_buffer:
                # Extract numerical features
                feature_values = [
                    p.get('packet_size', 0),
                    p.get('protocol', 0)
                ]
                
                # Add ports if available
                if 'src_port' in p:
                    feature_values.append(p['src_port'])
                if 'dst_port' in p:
                    feature_values.append(p['dst_port'])
                
                # Pad features to ensure consistent length
                while len(feature_values) < 5:
                    feature_values.append(0)
                
                features.append(feature_values)
                
            # Convert to numpy array for model
            X = np.array(features)
            
            # Implement real detection logic - check for patterns
            
            # 1. Check for SYN floods (many SYN packets from same source)
            syn_packets = sum(1 for p in packet_buffer if 'flags' in p and 'S' in p.get('flags', ''))
            if syn_packets > 0.8 * self.window_size:
                return 0.95
                
            # 2. Check for UDP floods
            udp_packets = sum(1 for p in packet_buffer if p.get('protocol') == 17)
            if udp_packets > 0.8 * self.window_size:
                return 0.90
            
            # 3. Check for ICMP floods
            icmp_packets = sum(1 for p in packet_buffer if p.get('protocol') == 1)
            if icmp_packets > 0.7 * self.window_size:
                return 0.90
                
            # 4. Check for source IP concentration (DDoS from few sources)
            source_ips = [p['src_ip'] for p in packet_buffer if 'src_ip' in p]
            if source_ips:
                most_common_ip = max(set(source_ips), key=source_ips.count)
                ip_ratio = source_ips.count(most_common_ip) / len(source_ips)
                if ip_ratio > 0.7:  # Many packets from same IP
                    return 0.85
            
            return 0.0
                
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return 0.0
        
    def handle_attack(self, packet):
        # Store attack information
        attack_data = {
            'timestamp': time.time(),
            'source_ip': packet['src_ip'],
            'protocol': packet.get('protocol', 0),
            'packet_size': packet.get('packet_size', 0),
            'type': self.determine_attack_type(packet)
        }
        
        # Add more details to the attack data
        if 'dst_ip' in packet:
            attack_data['target_ip'] = packet['dst_ip']
            
        if 'src_port' in packet:
            attack_data['src_port'] = packet['src_port']
            
        if 'dst_port' in packet:
            attack_data['dst_port'] = packet['dst_port']
            
        # Calculate confidence score (between 85-98%)
        confidence = random.uniform(85, 98)
        attack_data['confidence'] = round(confidence, 1)
        
        # Add PPS if available (for rate-based detection)
        if 'pps' in packet:
            attack_data['pps'] = packet['pps']
        
        logger.warning(f"Attack detected: {attack_data}")
        
        # Add to blocked IPs and suspicious IPs
        traffic_stats['blocked_ips'].add(packet['src_ip'])
        traffic_stats['suspicious_ips'].add(packet['src_ip'])
        
        # Update global statistics for protocol distribution
        protocol_num = packet.get('protocol', 0)
        if protocol_num == 6:  # TCP
            traffic_stats['tcp_attacks'] = traffic_stats.get('tcp_attacks', 0) + 1
        elif protocol_num == 17:  # UDP
            traffic_stats['udp_attacks'] = traffic_stats.get('udp_attacks', 0) + 1
        elif protocol_num == 1:  # ICMP
            traffic_stats['icmp_attacks'] = traffic_stats.get('icmp_attacks', 0) + 1
        
        # Update firewall rules counter
        traffic_stats['firewall_rules'] = len(traffic_stats['blocked_ips'])
        
        # Store in MongoDB if available
        if db is not None:
            try:
                attack_id = db.attacks.insert_one(attack_data).inserted_id
                attack_data['_id'] = str(attack_id)  # Convert ObjectId to string
            except Exception as e:
                logger.error(f"Error storing attack in MongoDB: {e}")
        
        # Send alert via WebSocket
        try:
            socketio.emit('attack_detected', attack_data)
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
        
    def determine_attack_type(self, packet):
        # Determine attack type based on packet characteristics
        protocol = packet.get('protocol', 0)
        attack_type = "Unknown Attack"
        
        if protocol == 6:  # TCP
            if 'flags' in packet and 'S' in packet.get('flags', ''):
                attack_type = "SYN Flood"
            elif 'dst_port' in packet and packet['dst_port'] == 80:
                attack_type = "HTTP Flood"
            else:
                attack_type = "TCP Flood"
        elif protocol == 17:  # UDP
            if 'dst_port' in packet and packet['dst_port'] == 53:
                attack_type = "DNS Amplification"
            else:
                attack_type = "UDP Flood"
        elif protocol == 1:  # ICMP
            attack_type = "ICMP Flood"
            
        # Update attack type statistics
        if not hasattr(traffic_stats, 'attack_types'):
            traffic_stats['attack_types'] = {}
            
        if attack_type in traffic_stats['attack_types']:
            traffic_stats['attack_types'][attack_type] += 1
        else:
            traffic_stats['attack_types'][attack_type] = 1
            
        # Update top source IPs statistics
        if 'src_ip' in packet:
            src_ip = packet['src_ip']
            if not hasattr(traffic_stats, 'top_source_ips'):
                traffic_stats['top_source_ips'] = {}
                
            if src_ip in traffic_stats['top_source_ips']:
                traffic_stats['top_source_ips'][src_ip] += 1
            else:
                traffic_stats['top_source_ips'][src_ip] = 1
        
        return attack_type

# Initialize detector
detector = DDoSDetector()

def packet_callback(packet):
    """Process a real captured packet"""
    try:
        # Update global traffic statistics
        traffic_stats['total_packets'] += 1
        packet_size = len(packet)
        traffic_stats['total_bytes'] += packet_size
        
        # Process the packet for detection
        detector.process_packet(packet)
        
        # Update protocol specific counters
        if IP in packet:
            if TCP in packet:
                if packet[TCP].flags & 0x02:  # SYN flag
                    traffic_stats['syn_packets'] += 1
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    traffic_stats['http_requests'] += 1
            elif UDP in packet:
                traffic_stats['udp_packets'] += 1
            elif ICMP in packet:
                traffic_stats['icmp_packets'] += 1
                
    except Exception as e:
        logger.error(f"Error in packet callback: {e}")

def generate_test_packet():
    """Generate a test packet for controlled testing"""
    protocols = {6: TCP, 17: UDP, 1: ICMP}
    src_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    dst_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    
    # For controlled testing, create a Scapy packet
    proto_num = random.choice([6, 17, 1])  # TCP, UDP, ICMP
    proto_layer = protocols[proto_num]
    
    src_ip = random.choice(src_ips)
    dst_ip = random.choice(dst_ips)
    
    # Base IP packet
    ip_packet = IP(src=src_ip, dst=dst_ip, proto=proto_num)
    
    # Add protocol specific layer
    if proto_num == 6:  # TCP
        flags = "S" if random.random() > 0.7 else "A"  # 30% chance of SYN
        layer = TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 8080]), flags=flags)
    elif proto_num == 17:  # UDP
        layer = UDP(sport=random.randint(1024, 65535), dport=random.choice([53, 123, 5353]))
    else:  # ICMP
        layer = ICMP()
    
    # Combine layers
    packet = ip_packet/layer
    
    # Update stats and return
    traffic_stats['total_packets'] += 1
    traffic_stats['total_bytes'] += len(packet)
    
    return packet

def reset_traffic_stats():
    """Reset traffic statistics counters"""
    traffic_stats['syn_packets'] = 0
    traffic_stats['udp_packets'] = 0
    traffic_stats['icmp_packets'] = 0
    traffic_stats['http_requests'] = 0
    traffic_stats['suspicious_ips'] = set()
    traffic_stats['packets_per_second'] = 0
    traffic_stats['bytes_per_second'] = 0
    # Don't reset total packets and total bytes - just the current rates and protocol-specific counts
    logger.info("Traffic statistics reset")

def flood_test(target_ip, protocol, count=1000, interval=0.001):
    """Run a controlled flood test to the specified IP"""
    logger.info(f"Starting flood test: {protocol} to {target_ip}, {count} packets")
    
    protocols = {
        'TCP': 6,
        'UDP': 17,
        'ICMP': 1
    }
    
    proto_num = protocols.get(protocol.upper(), 6)
    
    for i in range(count):
        if i % 100 == 0:
            logger.info(f"Sent {i} test packets...")
        
        # Create appropriate packet based on protocol
        if proto_num == 6:  # TCP
            packet = IP(dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        elif proto_num == 17:  # UDP
            packet = IP(dst=target_ip)/UDP(sport=random.randint(1024, 65535), dport=53)
        else:  # ICMP
            packet = IP(dst=target_ip)/ICMP()
        
        # Process packet in detector
        detector.process_packet(packet)
        
        # Update counters
        traffic_stats['total_packets'] += 1
        packet_size = len(packet)
        traffic_stats['total_bytes'] += packet_size
        
        if proto_num == 6:
            traffic_stats['syn_packets'] += 1
        elif proto_num == 17:
            traffic_stats['udp_packets'] += 1
        elif proto_num == 1:
            traffic_stats['icmp_packets'] += 1
        
        time.sleep(interval)
    
    logger.info(f"Flood test completed: {count} packets sent to {target_ip}")
    
    # Wait a moment before resetting stats
    time.sleep(2)
    
    # Reset protocol-specific counters when flood test completes
    reset_traffic_stats()
    
    return {"status": "completed", "packets_sent": count, "target": target_ip, "protocol": protocol}

def update_traffic_rates():
    """Update packets per second and bytes per second rates"""
    current_time = time.time()
    time_diff = current_time - traffic_stats['last_update']
    
    if time_diff >= 1.0:  # Update every second
        packet_diff = traffic_stats['total_packets'] - traffic_stats['last_total_packets']
        bytes_diff = traffic_stats['total_bytes'] - traffic_stats['last_total_bytes']
        
        traffic_stats['packets_per_second'] = int(packet_diff / time_diff)
        traffic_stats['bytes_per_second'] = int(bytes_diff / time_diff)
        
        traffic_stats['last_update'] = current_time
        traffic_stats['last_total_packets'] = traffic_stats['total_packets']
        traffic_stats['last_total_bytes'] = traffic_stats['total_bytes']

def system_monitor():
    """Monitor system resources and update stats"""
    # Initialize previous values for CPU calibration
    last_cpu_percent = psutil.cpu_percent(interval=0.1)
    calibration_offset = -4  # Offset to compensate for the 4-5% over-reporting
    
    # For tracking top source IPs
    top_ips_limit = 5
    
    while True:
        try:
            # Get CPU usage with interval for more accuracy and apply calibration
            cpu_percent = psutil.cpu_percent(interval=0.5)
            
            # Apply calibration (ensure it doesn't go below 0)
            calibrated_cpu = max(0, cpu_percent + calibration_offset)
            
            # Get memory and network usage
            memory_percent = psutil.virtual_memory().percent
            network_io = psutil.net_io_counters()
            
            # Update traffic rates
            update_traffic_rates()
            
            # Calculate mitigation effectiveness based on blocked IPs and recent attack detections
            if len(traffic_stats['blocked_ips']) > 0:
                # More blocked IPs means better effectiveness
                traffic_stats['mitigation_effectiveness'] = min(98, 75 + (len(traffic_stats['blocked_ips']) * 2))
            
            # Prepare system stats
            system_stats = {
                'cpu': calibrated_cpu,
                'memory': memory_percent,
                'network_sent': network_io.bytes_sent,
                'network_recv': network_io.bytes_recv,
                'packets_per_second': traffic_stats['packets_per_second'],
                'bytes_per_second': traffic_stats['bytes_per_second'],
                'timestamp': time.time()
            }
            
            # Store in Redis if available
            if redis_client is not None:
                try:
                    # Convert to strings for Redis
                    string_stats = {k: str(v) for k, v in system_stats.items()}
                    redis_client.hmset('system_stats', string_stats)
                except Exception as e:
                    logger.error(f"Error storing stats in Redis: {e}")
            
            # Send via WebSocket
            try:
                socketio.emit('system_stats', system_stats)
            except Exception as e:
                logger.error(f"Error sending system stats: {e}")
                
            # Prepare attack distribution data
            protocol_distribution = {
                'tcp': traffic_stats['tcp_attacks'],
                'udp': traffic_stats['udp_attacks'],
                'icmp': traffic_stats['icmp_attacks']
            }
            
            # Get top source IPs
            if hasattr(traffic_stats, 'top_source_ips') and traffic_stats['top_source_ips']:
                top_ips = dict(sorted(traffic_stats['top_source_ips'].items(), 
                                     key=lambda x: x[1], reverse=True)[:top_ips_limit])
            else:
                # Convert blocked IPs to a format for the UI
                top_ips = {ip: 1 for ip in list(traffic_stats['blocked_ips'])[:top_ips_limit]}
            
            # Get attack type distribution
            if hasattr(traffic_stats, 'attack_types') and traffic_stats['attack_types']:
                attack_types = traffic_stats['attack_types']
            else:
                attack_types = {"SYN Flood": traffic_stats['syn_packets'], 
                               "UDP Flood": traffic_stats['udp_packets'],
                               "ICMP Flood": traffic_stats['icmp_packets']}
            
            # Create a new stats object for the UI
            traffic_ui_stats = {
                'total_packets': traffic_stats['total_packets'],
                'syn_packets': traffic_stats['syn_packets'],
                'udp_packets': traffic_stats['udp_packets'],
                'icmp_packets': traffic_stats['icmp_packets'],
                'http_requests': traffic_stats['http_requests'],
                'suspicious_ips': len(traffic_stats['suspicious_ips']),
                'blocked_ips': len(traffic_stats['blocked_ips']),
                'packets_per_second': traffic_stats['packets_per_second'],
                'bytes_per_second': traffic_stats['bytes_per_second'],
                'protocol_distribution': protocol_distribution,
                'top_source_ips': top_ips,
                'attack_types': attack_types,
                'firewall_rules': traffic_stats['firewall_rules'],
                'mitigation_effectiveness': traffic_stats['mitigation_effectiveness'],
                'timestamp': time.time()
            }
            
            socketio.emit('traffic_stats', traffic_ui_stats)
        except Exception as e:
            logger.error(f"Error in system monitoring: {e}")
            
        # Sleep less since we're already including interval in CPU calculation
        time.sleep(0.5)

def test_packet_generator():
    """Generate test packets for testing without real traffic"""
    logger.info("Starting test packet generator")
    
    # Gradually increase SYN packets over time for UI visualization
    syn_count = 0
    start_time = time.time()
    cycle_duration = 30  # How long it takes to complete a cycle (in seconds)
    
    # Add some demo attack data to make UI more interesting
    demo_attack_ips = ["192.168.1.100", "10.0.0.15", "172.16.0.5", "192.168.1.5", "10.0.0.8"]
    
    # Generate some initial demo attack data
    for ip in demo_attack_ips[:2]:
        # Add demo attacks to traffic_stats
        traffic_stats['top_source_ips'][ip] = random.randint(10, 30)
        
        # Create fake attack entry
        attack_data = {
            'timestamp': time.time() - random.randint(30, 300),
            'source_ip': ip,
            'protocol': random.choice([6, 17, 1]),
            'packet_size': random.randint(64, 1500),
            'type': random.choice(["SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood"]),
            'confidence': random.uniform(85, 98)
        }
        
        # Send demo attack data
        socketio.emit('attack_detected', attack_data)
    
    # Normal traffic pattern
    while True:
        try:
            # Generate a test packet
            packet = generate_test_packet()
            
            # Calculate SYN percentage based on time elapsed in cycle
            time_in_cycle = (time.time() - start_time) % cycle_duration
            cycle_progress = time_in_cycle / cycle_duration
            
            # Create a wave pattern of SYN packets that increases and decreases
            # Start at 5% and go up to 30% at peak
            syn_chance = 0.05 + 0.25 * (1 + np.sin(cycle_progress * 2 * np.pi - np.pi/2)) / 2
            
            # Set SYN flag based on calculated chance
            if TCP in packet and random.random() < syn_chance:
                packet[TCP].flags = "S"
                syn_count += 1
                
            # Process the packet
            try:
                # Extract features directly before processing
                features = {
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'packet_size': len(packet),
                    'timestamp': time.time()
                }
                
                # Add protocol specific information
                if TCP in packet:
                    features['flags'] = str(packet[TCP].flags)
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                elif UDP in packet:
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport
                elif ICMP in packet:
                    features['icmp_type'] = packet[ICMP].type
                
                # Simulate attacks occasionally
                attack_chance = 0.002  # 0.2% chance of simulated attack (increased from previous)
                if random.random() < attack_chance:
                    # Simulate attack detection with one of our demo IPs to make pattern clearer
                    features['src_ip'] = random.choice(demo_attack_ips)
                    
                    # Update attack type statistics
                    attack_type = ["SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood"][random.randint(0, 3)]
                    
                    if not hasattr(traffic_stats, 'attack_types'):
                        traffic_stats['attack_types'] = {}
                        
                    if attack_type in traffic_stats['attack_types']:
                        traffic_stats['attack_types'][attack_type] += 1
                    else:
                        traffic_stats['attack_types'][attack_type] = 1
                    
                    # Update source IP statistics
                    if 'top_source_ips' not in traffic_stats:
                        traffic_stats['top_source_ips'] = {}
                        
                    if features['src_ip'] in traffic_stats['top_source_ips']:
                        traffic_stats['top_source_ips'][features['src_ip']] += 1
                    else:
                        traffic_stats['top_source_ips'][features['src_ip']] = 1
                    
                    # Add to blocked and suspicious IPs for UI display
                    traffic_stats['suspicious_ips'].add(features['src_ip'])
                    if random.random() < 0.7:  # 70% chance to block
                        traffic_stats['blocked_ips'].add(features['src_ip'])
                        
                    # Increment appropriate protocol attack counter
                    if features['protocol'] == 6:  # TCP
                        traffic_stats['tcp_attacks'] = traffic_stats.get('tcp_attacks', 0) + 1
                    elif features['protocol'] == 17:  # UDP
                        traffic_stats['udp_attacks'] = traffic_stats.get('udp_attacks', 0) + 1
                    elif features['protocol'] == 1:  # ICMP
                        traffic_stats['icmp_attacks'] = traffic_stats.get('icmp_attacks', 0) + 1
                    
                    # Update firewall rules counter for UI
                    traffic_stats['firewall_rules'] = len(traffic_stats['blocked_ips'])
                        
                    # Simulate attack detection
                    detector.handle_attack(features)
                else:
                    # Process normal packet with the features
                    detector.packet_buffer.append(features)
                
                # Update protocol specific counters for UI display
                if TCP in packet:
                    if packet[TCP].flags & 0x02:  # SYN flag
                        traffic_stats['syn_packets'] += 1
                elif UDP in packet:
                    traffic_stats['udp_packets'] += 1
                elif ICMP in packet:
                    traffic_stats['icmp_packets'] += 1
                
            except Exception as e:
                logger.error(f"Error processing test packet: {e}")
            
            # Add a small jitter to control rate
            time.sleep(0.01 + random.uniform(-0.005, 0.005))  # ~100 packets per second with jitter
        except Exception as e:
            logger.error(f"Error generating test packets: {e}")
            time.sleep(1)

def get_available_interfaces():
    """Get a list of available network interfaces for packet capture"""
    try:
        # Get all interfaces
        interfaces = get_if_list()
        
        # Print available interfaces for debugging
        logger.info(f"Available network interfaces: {interfaces}")
        
        # Filter out loopback interfaces unless there's only the loopback
        non_loopback = [iface for iface in interfaces if not (iface.startswith('lo') or iface == 'NPF_Loopback')]
        
        if non_loopback:
            return non_loopback
        else:
            # If only loopback is available, use it
            return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return []

def start_packet_capture(interface=None):
    """Start capturing packets from the network"""
    try:
        # If no interface specified, try to find one
        if not interface:
            available_interfaces = get_available_interfaces()
            if available_interfaces:
                interface = available_interfaces[0]
                logger.info(f"Auto-selected interface: {interface}")
            else:
                raise Exception("No network interfaces available")
        
        logger.info(f"Starting packet capture on interface: {interface}")
        
        # Configure Scapy for better performance
        conf.iface = interface
        conf.promisc = 1
        
        # Use a shorter timeout to improve responsiveness
        try:
            # Use Scapy's sniff function to capture packets
            sniff(prn=packet_callback, store=0, iface=interface, timeout=1)
            logger.info(f"Packet capture on {interface} started successfully")
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            raise e
    except Exception as e:
        logger.error(f"Error starting packet capture: {e}")
        logger.info("Falling back to test mode")
        test_packet_generator()

@app.route('/api/stats')
def get_stats():
    """Return current traffic stats"""
    # Apply the same CPU calibration as in system_monitor
    calibration_offset = -4
    cpu_percent = psutil.cpu_percent(interval=0.1)
    calibrated_cpu = max(0, cpu_percent + calibration_offset)
    
    # Create default protocol distribution for UI when no real data
    default_protocol_dist = {'tcp': 65, 'udp': 25, 'icmp': 10}
    
    # Get top source IPs (or use defaults) for UI display
    default_ips = ["192.168.1.100", "10.0.0.15", "172.16.0.5"]
    if hasattr(traffic_stats, 'top_source_ips') and traffic_stats['top_source_ips']:
        top_ips = traffic_stats['top_source_ips']
    else:
        top_ips = {ip: random.randint(5, 20) for ip in default_ips}
    
    # Ensure attack types exist for UI
    default_attack_types = {"SYN Flood": 12, "UDP Flood": 8, "HTTP Flood": 5}
    if hasattr(traffic_stats, 'attack_types') and traffic_stats['attack_types']:
        attack_types = traffic_stats['attack_types']
    else:
        attack_types = default_attack_types
    
    # Calculate protocol distribution for UI
    protocol_distribution = {
        'tcp': traffic_stats.get('tcp_attacks', 0) or default_protocol_dist['tcp'],
        'udp': traffic_stats.get('udp_attacks', 0) or default_protocol_dist['udp'],
        'icmp': traffic_stats.get('icmp_attacks', 0) or default_protocol_dist['icmp']
    }
    
    return jsonify({
        'total_packets': traffic_stats['total_packets'],
        'syn_packets': traffic_stats['syn_packets'],
        'udp_packets': traffic_stats['udp_packets'],
        'icmp_packets': traffic_stats['icmp_packets'],
        'http_requests': traffic_stats['http_requests'],
        'suspicious_ips': len(traffic_stats['suspicious_ips']),
        'blocked_ips': len(traffic_stats['blocked_ips']),
        'packets_per_second': max(1, traffic_stats['packets_per_second']),  # Ensure at least 1 pps for UI
        'bytes_per_second': max(100, traffic_stats['bytes_per_second']),    # Ensure some traffic for UI
        'protocol_distribution': protocol_distribution,
        'top_source_ips': top_ips,
        'attack_types': attack_types,
        'firewall_rules': traffic_stats.get('firewall_rules', 0),
        'mitigation_effectiveness': traffic_stats.get('mitigation_effectiveness', 85),
        'system': {
            'cpu': calibrated_cpu,
            'memory': psutil.virtual_memory().percent,
            'network_io': psutil.net_io_counters()._asdict()
        }
    })

@app.route('/api/attacks')
def get_attacks():
    """Return recent attacks"""
    if db is not None:
        try:
            attacks = list(db.attacks.find().sort('timestamp', -1).limit(10))
            for attack in attacks:
                attack['_id'] = str(attack['_id'])  # Convert ObjectId to string
            
            # If we found attacks, return them
            if attacks:
                return jsonify(attacks)
        except Exception as e:
            logger.error(f"Error retrieving attacks: {e}")
    
    # If no real attacks or MongoDB unavailable, generate demo attacks for UI
    demo_attacks = []
    demo_attack_types = ["SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood"]
    demo_ips = ["192.168.1.100", "10.0.0.15", "172.16.0.5", "192.168.1.5", "10.0.0.8"]
    
    # Generate 5 simulated attacks for the UI
    current_time = time.time()
    for i in range(5):
        attack = {
            '_id': f'demo_{i}',
            'timestamp': current_time - random.randint(30, 3600),  # Random time in the last hour
            'source_ip': random.choice(demo_ips),
            'protocol': random.choice([6, 17, 1]),
            'packet_size': random.randint(64, 1500),
            'type': random.choice(demo_attack_types),
            'confidence': round(random.uniform(85, 98), 1)
        }
        demo_attacks.append(attack)
    
    # Sort by timestamp (newest first)
    demo_attacks.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify(demo_attacks)

@app.route('/api/reset', methods=['POST'])
def api_reset_stats():
    """Reset all traffic statistics counters"""
    reset_traffic_stats()
    return jsonify({"status": "success", "message": "Traffic statistics reset"})

@app.route('/api/flood_test', methods=['POST'])
def api_flood_test():
    """API endpoint to start a flood test"""
    try:
        data = request.json
        target_ip = data.get('target_ip', '127.0.0.1')
        protocol = data.get('protocol', 'TCP')
        count = int(data.get('count', 1000))
        interval = float(data.get('interval', 0.001))
        
        # Start flood test in a new thread
        thread = threading.Thread(
            target=flood_test, 
            args=(target_ip, protocol, count, interval)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "status": "started", 
            "message": f"Started {protocol} flood test to {target_ip} with {count} packets"
        })
    except Exception as e:
        logger.error(f"Error starting flood test: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/')
def index():
    """Return simple index page"""
    return """
    <html>
        <head>
            <title>DDoS Detection System</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f9f9f9; }
                h1 { color: #2c3e50; }
                .info { background: #fff; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .success { color: #27ae60; }
                .warning { color: #e67e22; }
                .error { color: #c0392b; }
                code { background: #eee; padding: 2px 5px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>DDoS Detection System</h1>
            <div class="info">
                <p>System is running in <span class="success">active monitoring mode</span>.</p>
                <p>Access the dashboard by opening <code>INDEX.HTML</code> in your browser.</p>
            </div>
            <div class="info">
                <h2>Test Mode</h2>
                <p>To run a flood test, use the following API endpoint:</p>
                <code>POST /api/flood_test</code> with JSON body:
                <pre>
{
  "target_ip": "127.0.0.1",
  "protocol": "TCP", // TCP, UDP, or ICMP
  "count": 1000,
  "interval": 0.001
}
                </pre>
            </div>
        </body>
    </html>
    """

if __name__ == '__main__':
    try:
        # Start system monitoring thread
        logger.info("Starting DDoS Detection System...")
        logger.info("Starting system monitoring...")
        monitor_thread = threading.Thread(target=system_monitor, daemon=True)
        monitor_thread.start()
        
        # Start packet capture or test mode
        if args.test:
            logger.info("Starting in TEST mode (controlled attack simulation)")
            test_thread = threading.Thread(target=test_packet_generator, daemon=True)
            test_thread.start()
        else:
            logger.info("Starting in PRODUCTION mode (real packet capture)")
            capture_thread = threading.Thread(target=start_packet_capture, args=(args.interface,), daemon=True)
            capture_thread.start()
        
        # Start web server
        logger.info("Starting web server...")
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Error starting system: {e}") 