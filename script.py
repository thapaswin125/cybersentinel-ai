# Create Python requirements file
requirements = """# CyberSentinel AI Requirements
# Core Framework
flask==2.3.3
fastapi==0.104.1
uvicorn==0.24.0
celery==5.3.1
redis==4.6.0

# Machine Learning & AI
tensorflow==2.13.0
torch==2.0.1
torchvision==0.15.2
scikit-learn==1.3.0
numpy==1.24.3
pandas==2.0.3
matplotlib==3.7.2
seaborn==0.12.2

# Data Processing
pymisp==2.4.173
stix2==3.0.1
taxii2-client==2.3.0
requests==2.31.0
beautifulsoup4==4.12.2
scrapy==2.11.0

# Network Security
scapy==2.5.0
python-nmap==0.7.1
pyshark==0.6
netaddr==0.8.0
dnspython==2.4.2

# Cryptography & Security
cryptography==41.0.4
pycryptodome==3.18.0
paramiko==3.3.1
pyotp==2.9.0
python-jose==3.3.0

# Database & Storage
postgresql-adapter==0.1.0
psycopg2-binary==2.9.7
elasticsearch==8.9.0
pymongo==4.5.0
sqlalchemy==2.0.21

# Web & API
aiohttp==3.8.5
websockets==11.0.3
flask-cors==4.0.0
flask-jwt-extended==4.5.2
pydantic==2.3.0

# Monitoring & Logging
prometheus-client==0.17.1
python-json-logger==2.0.7
loguru==0.7.0
sentry-sdk==1.32.0

# Testing & Development
pytest==7.4.0
pytest-asyncio==0.21.1
black==23.7.0
flake8==6.0.0
mypy==1.5.1

# Containerization & Deployment
docker==6.1.3
kubernetes==27.2.0
gunicorn==21.2.0
supervisor==4.2.5

# Additional Security Tools
yara-python==4.3.1
pefile==2023.2.7
python-magic==0.4.27
volatility3==2.4.1
"""

# Save to file
with open('requirements.txt', 'w') as f:
    f.write(requirements.strip())

print("✅ Created requirements.txt file")

# Create a sample AI threat detection module
ai_threat_detector = '''"""
CyberSentinel AI - Threat Detection Module
Advanced machine learning-based threat detection system
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
import logging
from datetime import datetime, timedelta
import pickle

class ThreatDetectionEngine:
    """
    Advanced AI-powered threat detection engine combining multiple ML algorithms
    """
    
    def __init__(self, model_path=None):
        self.isolation_forest = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.lstm_model = None
        self.model_path = model_path
        self.threat_threshold = 0.5
        
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def preprocess_network_data(self, network_data):
        """
        Preprocess network traffic data for ML analysis
        """
        try:
            # Convert network features to numerical format
            features = [
                'packet_size', 'protocol_type', 'duration', 
                'src_bytes', 'dst_bytes', 'flow_duration',
                'inter_packet_time', 'packet_rate'
            ]
            
            # Handle missing values and normalize
            processed_data = network_data[features].fillna(0)
            normalized_data = self.scaler.fit_transform(processed_data)
            
            return normalized_data
            
        except Exception as e:
            self.logger.error(f"Error preprocessing network data: {e}")
            return None
    
    def train_isolation_forest(self, normal_traffic_data):
        """
        Train Isolation Forest model on normal network traffic
        """
        try:
            processed_data = self.preprocess_network_data(normal_traffic_data)
            if processed_data is not None:
                self.isolation_forest.fit(processed_data)
                self.logger.info("Isolation Forest model trained successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Error training Isolation Forest: {e}")
            return False
    
    def build_lstm_model(self, input_shape):
        """
        Build LSTM neural network for sequence-based threat detection
        """
        try:
            model = Sequential([
                LSTM(128, return_sequences=True, input_shape=input_shape),
                Dropout(0.2),
                LSTM(64, return_sequences=False),
                Dropout(0.2),
                Dense(32, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            self.lstm_model = model
            self.logger.info("LSTM model built successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error building LSTM model: {e}")
            return False
    
    def detect_anomalies(self, network_data):
        """
        Detect network anomalies using ensemble of ML models
        """
        results = []
        
        try:
            processed_data = self.preprocess_network_data(network_data)
            if processed_data is None:
                return results
            
            # Isolation Forest predictions
            if_predictions = self.isolation_forest.predict(processed_data)
            if_scores = self.isolation_forest.decision_function(processed_data)
            
            # Process results
            for i, (prediction, score) in enumerate(zip(if_predictions, if_scores)):
                threat_detected = prediction == -1  # -1 indicates anomaly
                confidence = abs(score)
                
                # Classify threat type based on network characteristics
                threat_type = self.classify_threat_type(network_data.iloc[i])
                
                result = {
                    'timestamp': datetime.now().isoformat(),
                    'threat_id': f"TH{str(i+1).zfill(3)}",
                    'threat_detected': threat_detected,
                    'confidence': float(confidence),
                    'threat_type': threat_type,
                    'source_ip': network_data.iloc[i].get('src_ip', 'unknown'),
                    'destination_ip': network_data.iloc[i].get('dst_ip', 'unknown'),
                    'ml_model': 'Isolation Forest',
                    'severity': self.calculate_severity(confidence, threat_type)
                }
                
                if threat_detected:
                    results.append(result)
                    
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
            
        return results
    
    def classify_threat_type(self, network_sample):
        """
        Classify the type of threat based on network characteristics
        """
        # Simple rule-based classification (can be enhanced with ML)
        packet_rate = network_sample.get('packet_rate', 0)
        packet_size = network_sample.get('packet_size', 0)
        duration = network_sample.get('duration', 0)
        
        if packet_rate > 1000:
            return "DDoS Attack"
        elif packet_size < 64 and duration > 300:
            return "Port Scanning"
        elif 'malware' in str(network_sample.get('payload', '')).lower():
            return "Malware Communication"
        elif 'phish' in str(network_sample.get('payload', '')).lower():
            return "Phishing Campaign"
        else:
            return "Unknown Anomaly"
    
    def calculate_severity(self, confidence, threat_type):
        """
        Calculate threat severity based on confidence and type
        """
        base_severity = {
            "DDoS Attack": 0.8,
            "Malware Communication": 0.9,
            "Phishing Campaign": 0.6,
            "Port Scanning": 0.4,
            "Unknown Anomaly": 0.5
        }.get(threat_type, 0.5)
        
        # Adjust by confidence
        adjusted_severity = base_severity * confidence
        
        if adjusted_severity >= 0.8:
            return "Critical"
        elif adjusted_severity >= 0.6:
            return "High"
        elif adjusted_severity >= 0.4:
            return "Medium"
        else:
            return "Low"
    
    def save_model(self, filepath):
        """Save trained models to disk"""
        try:
            model_data = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'threshold': self.threat_threshold
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
                
            if self.lstm_model:
                self.lstm_model.save(f"{filepath}_lstm.h5")
                
            self.logger.info(f"Models saved to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
            return False
    
    def load_model(self, filepath):
        """Load trained models from disk"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
                
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.threat_threshold = model_data['threshold']
            
            # Try to load LSTM model if it exists
            try:
                from tensorflow.keras.models import load_model
                self.lstm_model = load_model(f"{filepath}_lstm.h5")
            except:
                self.logger.warning("LSTM model not found or could not be loaded")
                
            self.logger.info(f"Models loaded from {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            return False

# Example usage
if __name__ == "__main__":
    # Initialize threat detection engine
    detector = ThreatDetectionEngine()
    
    # Sample network data (in real implementation, this would come from network monitoring)
    sample_data = pd.DataFrame({
        'packet_size': [64, 1500, 32, 128, 2000],
        'protocol_type': [1, 2, 1, 3, 2],
        'duration': [0.5, 2.0, 0.1, 5.0, 10.0],
        'src_bytes': [1024, 4096, 256, 2048, 8192],
        'dst_bytes': [512, 2048, 128, 1024, 4096],
        'flow_duration': [1.0, 3.0, 0.2, 6.0, 12.0],
        'inter_packet_time': [0.01, 0.05, 0.001, 0.02, 0.1],
        'packet_rate': [100, 50, 1000, 200, 20],
        'src_ip': ['192.168.1.100', '10.0.0.1', '185.220.101.42', '172.16.1.1', '203.45.67.89'],
        'dst_ip': ['8.8.8.8', '192.168.1.1', '192.168.1.100', '10.0.0.100', '172.16.1.100']
    })
    
    # Train on sample data (normally you'd use a larger dataset of normal traffic)
    detector.train_isolation_forest(sample_data)
    
    # Detect threats
    threats = detector.detect_anomalies(sample_data)
    
    print("\\n=== CyberSentinel AI Threat Detection Results ===")
    for threat in threats:
        print(f"Threat ID: {threat['threat_id']}")
        print(f"Type: {threat['threat_type']}")
        print(f"Severity: {threat['severity']}")
        print(f"Confidence: {threat['confidence']:.2f}")
        print(f"Source IP: {threat['source_ip']}")
        print("-" * 50)
'''

# Save AI threat detection module
with open('ai_threat_detector.py', 'w') as f:
    f.write(ai_threat_detector)

print("✅ Created ai_threat_detector.py")