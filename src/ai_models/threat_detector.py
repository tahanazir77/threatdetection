"""
AI-powered threat detection models
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow import keras
from loguru import logger
import joblib
import os
import json

@dataclass
class ThreatDetectionResult:
    """Threat detection result"""
    is_threat: bool
    threat_score: float
    threat_type: str
    confidence: float
    features: Dict[str, float]
    explanation: str

@dataclass
class AnomalyDetectionResult:
    """Anomaly detection result"""
    is_anomaly: bool
    anomaly_score: float
    anomaly_type: str
    confidence: float
    features: Dict[str, float]

class ThreatDetector:
    """AI-powered threat detection system"""
    
    def __init__(self, settings):
        self.settings = settings
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {}
        self.is_trained = False
        
        # Initialize models
        self._initialize_models()
        
    def _initialize_models(self):
        """Initialize AI models"""
        try:
            # Anomaly detection model
            self.models['anomaly'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Threat classification model
            self.models['threat_classifier'] = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            
            # Deep learning model for complex patterns
            self.models['deep_learning'] = self._create_deep_learning_model()
            
            # Feature scalers
            self.scalers['network'] = StandardScaler()
            self.scalers['system'] = StandardScaler()
            
            logger.info("AI models initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing models: {e}")
            raise
    
    def _create_deep_learning_model(self):
        """Create deep learning model for threat detection"""
        model = keras.Sequential([
            keras.layers.Dense(128, activation='relu', input_shape=(20,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def extract_network_features(self, packet_data: Dict) -> Dict[str, float]:
        """Extract features from network packet data"""
        features = {}
        
        try:
            # Basic packet features
            features['packet_size'] = float(packet_data.get('packet_size', 0))
            features['src_port'] = float(packet_data.get('src_port', 0))
            features['dst_port'] = float(packet_data.get('dst_port', 0))
            
            # Protocol features
            features['is_tcp'] = 1.0 if packet_data.get('protocol') == 6 else 0.0
            features['is_udp'] = 1.0 if packet_data.get('protocol') == 17 else 0.0
            features['is_icmp'] = 1.0 if packet_data.get('protocol') == 1 else 0.0
            
            # IP address features (simplified)
            src_ip = packet_data.get('src_ip', '0.0.0.0')
            dst_ip = packet_data.get('dst_ip', '0.0.0.0')
            
            # Convert IP to numeric features
            features['src_ip_numeric'] = self._ip_to_numeric(src_ip)
            features['dst_ip_numeric'] = self._ip_to_numeric(dst_ip)
            
            # Port-based features
            features['is_well_known_port'] = 1.0 if self._is_well_known_port(
                packet_data.get('dst_port', 0)
            ) else 0.0
            
            features['is_high_port'] = 1.0 if packet_data.get('dst_port', 0) > 1024 else 0.0
            
            # Additional features
            features['packet_ratio'] = features['packet_size'] / 1500.0  # Normalize to MTU
            features['port_difference'] = abs(features['src_port'] - features['dst_port'])
            
        except Exception as e:
            logger.error(f"Error extracting network features: {e}")
            # Return default features
            features = {f'feature_{i}': 0.0 for i in range(20)}
        
        return features
    
    def extract_system_features(self, metrics_data: Dict) -> Dict[str, float]:
        """Extract features from system metrics"""
        features = {}
        
        try:
            # CPU and memory features
            features['cpu_percent'] = float(metrics_data.get('cpu_percent', 0))
            features['memory_percent'] = float(metrics_data.get('memory_percent', 0))
            features['disk_usage'] = float(metrics_data.get('disk_usage', 0))
            
            # Network I/O features
            network_io = metrics_data.get('network_io', {})
            features['bytes_sent'] = float(network_io.get('bytes_sent', 0))
            features['bytes_recv'] = float(network_io.get('bytes_recv', 0))
            features['packets_sent'] = float(network_io.get('packets_sent', 0))
            features['packets_recv'] = float(network_io.get('packets_recv', 0))
            
            # Connection features
            features['active_connections'] = float(metrics_data.get('active_connections', 0))
            
            # Derived features
            features['network_ratio'] = (
                features['bytes_sent'] / (features['bytes_recv'] + 1)
            )
            features['packet_ratio'] = (
                features['packets_sent'] / (features['packets_recv'] + 1)
            )
            
            # Resource utilization
            features['resource_utilization'] = (
                features['cpu_percent'] + features['memory_percent'] + features['disk_usage']
            ) / 3.0
            
        except Exception as e:
            logger.error(f"Error extracting system features: {e}")
            # Return default features
            features = {f'sys_feature_{i}': 0.0 for i in range(20)}
        
        return features
    
    def _ip_to_numeric(self, ip: str) -> float:
        """Convert IP address to numeric value"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return sum(int(part) * (256 ** (3 - i)) for i, part in enumerate(parts))
            return 0.0
        except:
            return 0.0
    
    def _is_well_known_port(self, port: int) -> bool:
        """Check if port is well-known (0-1023)"""
        return 0 <= port <= 1023
    
    def detect_threat(self, packet_data: Dict, metrics_data: Dict) -> ThreatDetectionResult:
        """Detect threats using AI models"""
        try:
            # Extract features
            network_features = self.extract_network_features(packet_data)
            system_features = self.extract_system_features(metrics_data)
            
            # Combine features
            all_features = {**network_features, **system_features}
            
            # Convert to numpy array
            feature_vector = np.array(list(all_features.values())).reshape(1, -1)
            
            # Ensure we have enough features
            if feature_vector.shape[1] < 20:
                # Pad with zeros
                padded_features = np.zeros((1, 20))
                padded_features[0, :feature_vector.shape[1]] = feature_vector[0]
                feature_vector = padded_features
            
            # Anomaly detection
            anomaly_score = self.models['anomaly'].decision_function(feature_vector)[0]
            is_anomaly = anomaly_score < -0.1
            
            # Threat classification
            if self.is_trained:
                threat_prob = self.models['threat_classifier'].predict_proba(feature_vector)[0]
                threat_score = threat_prob[1] if len(threat_prob) > 1 else 0.0
            else:
                # Use simple heuristics for untrained model
                threat_score = self._simple_threat_detection(all_features)
            
            # Deep learning prediction
            if self.is_trained:
                dl_prediction = self.models['deep_learning'].predict(feature_vector)[0][0]
            else:
                dl_prediction = 0.5
            
            # Combine predictions
            final_threat_score = (threat_score + dl_prediction) / 2.0
            
            # Determine threat type
            threat_type = self._classify_threat_type(all_features, final_threat_score)
            
            # Calculate confidence
            confidence = min(abs(final_threat_score - 0.5) * 2, 1.0)
            
            # Generate explanation
            explanation = self._generate_explanation(all_features, final_threat_score, threat_type)
            
            return ThreatDetectionResult(
                is_threat=final_threat_score > self.settings.threat_threshold,
                threat_score=final_threat_score,
                threat_type=threat_type,
                confidence=confidence,
                features=all_features,
                explanation=explanation
            )
            
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            return ThreatDetectionResult(
                is_threat=False,
                threat_score=0.0,
                threat_type="unknown",
                confidence=0.0,
                features={},
                explanation="Error in threat detection"
            )
    
    def _simple_threat_detection(self, features: Dict[str, float]) -> float:
        """Simple heuristic threat detection for untrained models"""
        threat_score = 0.0
        
        # Check for suspicious patterns
        if features.get('is_high_port', 0) > 0 and features.get('packet_size', 0) > 1000:
            threat_score += 0.3
        
        if features.get('cpu_percent', 0) > 80:
            threat_score += 0.2
        
        if features.get('memory_percent', 0) > 90:
            threat_score += 0.2
        
        if features.get('active_connections', 0) > 100:
            threat_score += 0.3
        
        return min(threat_score, 1.0)
    
    def _classify_threat_type(self, features: Dict[str, float], threat_score: float) -> str:
        """Classify the type of threat"""
        if threat_score < 0.3:
            return "normal"
        elif threat_score < 0.6:
            return "suspicious"
        elif threat_score < 0.8:
            return "potential_threat"
        else:
            return "high_threat"
    
    def _generate_explanation(self, features: Dict[str, float], threat_score: float, threat_type: str) -> str:
        """Generate human-readable explanation"""
        explanations = []
        
        if features.get('cpu_percent', 0) > 80:
            explanations.append("High CPU usage detected")
        
        if features.get('memory_percent', 0) > 90:
            explanations.append("High memory usage detected")
        
        if features.get('active_connections', 0) > 100:
            explanations.append("Unusual number of active connections")
        
        if features.get('packet_size', 0) > 1000:
            explanations.append("Large packet size detected")
        
        if not explanations:
            explanations.append("No specific indicators detected")
        
        return f"Threat type: {threat_type}. " + ". ".join(explanations)
    
    def train_models(self, training_data: List[Dict]):
        """Train the AI models with historical data"""
        try:
            logger.info("Starting model training...")
            
            # Prepare training data
            X = []
            y = []
            
            for data in training_data:
                # Extract features
                network_features = self.extract_network_features(data.get('packet', {}))
                system_features = self.extract_system_features(data.get('metrics', {}))
                all_features = {**network_features, **system_features}
                
                # Convert to numpy array
                feature_vector = np.array(list(all_features.values()))
                if feature_vector.shape[0] < 20:
                    # Pad with zeros
                    padded_features = np.zeros(20)
                    padded_features[:feature_vector.shape[0]] = feature_vector
                    feature_vector = padded_features
                
                X.append(feature_vector)
                y.append(data.get('is_threat', 0))
            
            X = np.array(X)
            y = np.array(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train anomaly detection model
            self.models['anomaly'].fit(X_train)
            
            # Train threat classifier
            self.models['threat_classifier'].fit(X_train, y_train)
            
            # Train deep learning model
            self.models['deep_learning'].fit(
                X_train, y_train,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Evaluate models
            self._evaluate_models(X_test, y_test)
            
            self.is_trained = True
            logger.info("Model training completed successfully")
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            raise
    
    def _evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray):
        """Evaluate model performance"""
        try:
            # Evaluate threat classifier
            y_pred = self.models['threat_classifier'].predict(X_test)
            logger.info("Threat Classifier Performance:")
            logger.info(classification_report(y_test, y_pred))
            
            # Evaluate deep learning model
            dl_pred = self.models['deep_learning'].predict(X_test)
            dl_pred_binary = (dl_pred > 0.5).astype(int).flatten()
            logger.info("Deep Learning Model Performance:")
            logger.info(classification_report(y_test, dl_pred_binary))
            
        except Exception as e:
            logger.error(f"Error evaluating models: {e}")
    
    def save_models(self, model_path: str):
        """Save trained models"""
        try:
            os.makedirs(model_path, exist_ok=True)
            
            # Save scikit-learn models
            joblib.dump(self.models['anomaly'], f"{model_path}/anomaly_model.pkl")
            joblib.dump(self.models['threat_classifier'], f"{model_path}/threat_classifier.pkl")
            joblib.dump(self.scalers['network'], f"{model_path}/network_scaler.pkl")
            joblib.dump(self.scalers['system'], f"{model_path}/system_scaler.pkl")
            
            # Save deep learning model
            self.models['deep_learning'].save(f"{model_path}/deep_learning_model.h5")
            
            # Save model metadata
            metadata = {
                'is_trained': self.is_trained,
                'model_version': '1.0.0',
                'training_date': pd.Timestamp.now().isoformat()
            }
            
            with open(f"{model_path}/metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Models saved to {model_path}")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
            raise
    
    def load_models(self, model_path: str):
        """Load trained models"""
        try:
            if not os.path.exists(model_path):
                logger.warning(f"Model path {model_path} does not exist")
                return
            
            # Load scikit-learn models
            self.models['anomaly'] = joblib.load(f"{model_path}/anomaly_model.pkl")
            self.models['threat_classifier'] = joblib.load(f"{model_path}/threat_classifier.pkl")
            self.scalers['network'] = joblib.load(f"{model_path}/network_scaler.pkl")
            self.scalers['system'] = joblib.load(f"{model_path}/system_scaler.pkl")
            
            # Load deep learning model
            self.models['deep_learning'] = keras.models.load_model(f"{model_path}/deep_learning_model.h5")
            
            # Load metadata
            with open(f"{model_path}/metadata.json", 'r') as f:
                metadata = json.load(f)
                self.is_trained = metadata.get('is_trained', False)
            
            logger.info(f"Models loaded from {model_path}")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise
