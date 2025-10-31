import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
from typing import List, Dict, Tuple


class AnomalyDetector:
    """ML-based network anomaly detection using multiple algorithms"""
    
    def __init__(self, contamination: float = 0.1):
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'packet_length', 'ttl', 'src_port', 'dst_port',
            'tcp_window', 'protocol', 'flags'
        ]
        
    def preprocess_packet(self, packet: Dict) -> np.ndarray:
        """Convert packet dict to feature vector"""
        features = []
        
        # Numerical features
        features.append(packet.get('packet_length', 0))
        features.append(packet.get('ttl', 64))
        features.append(packet.get('src_port', 0))
        features.append(packet.get('dst_port', 0))
        features.append(packet.get('tcp_window', 0))
        
        # Protocol encoding
        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
        features.append(protocol_map.get(packet.get('protocol_type', 'TCP'), 0))
        
        # Flags
        features.append(packet.get('flags', 0))
        
        return np.array(features).reshape(1, -1)
    
    def train(self, packets: List[Dict]):
        """Train anomaly detection model on baseline traffic"""
        logger.info(f"Training anomaly detector on {len(packets)} packets")
        
        X = np.array([
            self.preprocess_packet(p).flatten()
            for p in packets
        ])
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.isolation_forest.fit(X_scaled)
        self.is_trained = True
        
        logger.info("Anomaly detector training complete")
    
    def detect_anomaly(self, packet: Dict) -> Tuple[bool, float]:
        """
        Detect if packet is anomalous
        Returns: (is_anomaly, anomaly_score)
        """
        if not self.is_trained:
            return False, 0.0
        
        X = self.preprocess_packet(packet)
        X_scaled = self.scaler.transform(X)
        
        # Get prediction and score
        prediction = self.isolation_forest.predict(X_scaled)[0]
        score = self.isolation_forest.score_samples(X_scaled)[0]
        
        # -1 indicates anomaly, 1 indicates normal
        is_anomaly = prediction == -1
        
        # Convert score to probability (0-1 range)
        anomaly_probability = 1 / (1 + np.exp(score))
        
        return is_anomaly, float(anomaly_probability)
    
    def save_model(self, filepath: str):
        """Save trained model to disk"""
        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model from disk"""
        model_data = joblib.load(filepath)
        self.isolation_forest = model_data['isolation_forest']
        self.scaler = model_data['scaler']
        self.is_trained = model_data['is_trained']
        logger.info(f"Model loaded from {filepath}")
