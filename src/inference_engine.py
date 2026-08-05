#!/usr/bin/env python3
"""
Task 2: Inference Engine - Production-ready model loading and prediction
Used by the main Network Guardian application.
"""

import joblib
import numpy as np
import warnings
warnings.filterwarnings('ignore')

from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass


@dataclass
class PredictionResult:
    """Result of anomaly detection prediction."""
    is_anomaly: bool
    confidence: float          # 0.0 - 1.0
    threat_type: str           # 'normal', 'anomaly', or specific attack type
    threat_category: str       # 'dos', 'probe', 'r2l', 'u2r', 'normal'
    model_used: str            # which model made the prediction
    flow_features: Dict[str, float]  # key features for alerting


class InferenceEngine:
    """
    Production inference engine for network anomaly detection.
    Loads ensemble models, preprocesses flow features, returns predictions.
    """
    
    # Attack category mapping (NSL-KDD / UNSW-NB15 taxonomy)
    ATTACK_CATEGORIES = {
        # DoS
        'neptune': 'dos', 'smurf': 'dos', 'back': 'dos', 'land': 'dos',
        'pod': 'dos', 'teardrop': 'dos', 'apache2': 'dos', 'udpstorm': 'dos',
        'processtable': 'dos', 'worm': 'dos',
        # Probe
        'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe',
        'mscan': 'probe', 'saint': 'probe',
        # R2L
        'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'phf': 'r2l',
        'multihop': 'r2l', 'warezclient': 'r2l', 'warezmaster': 'r2l',
        'xlock': 'r2l', 'xsnoop': 'r2l', 'snmpguess': 'r2l', 'snmpgetattack': 'r2l',
        'httptunnel': 'r2l', 'sendmail': 'r2l', 'named': 'r2l',
        # U2R
        'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r',
        'xterm': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r',
        # Normal
        'normal': 'normal'
    }
    
    def __init__(self, model_dir: Path = None, threshold: float = 0.6):
        """
        Initialize inference engine.
        
        Args:
            model_dir: Directory containing model artifacts
            threshold: Anomaly confidence threshold (0.0-1.0)
        """
        self.model_dir = model_dir or Path(__file__).parent.parent / "models"
        self.threshold = threshold
        
        # Model artifacts
        self.ensemble_model = None
        self.rf_model = None
        self.xgb_model = None
        self.lgb_model = None
        self.threat_classifier = None
        self.scaler = None
        self.encoders = None
        self.feature_names = None
        
        # Load all models
        self._load_models()
    
    def _load_models(self):
        """Load all model artifacts from disk."""
        print(f"📦 Loading models from {self.model_dir}")
        
        # Binary anomaly detection models
        self.ensemble_model = joblib.load(self.model_dir / "rf_anomaly_model.pkl")
        self.rf_model = joblib.load(self.model_dir / "rf_model.pkl")
        self.xgb_model = joblib.load(self.model_dir / "xgb_model.pkl")
        self.lgb_model = joblib.load(self.model_dir / "lgb_model.pkl")
        
        # Multi-class threat classifier
        try:
            self.threat_classifier = joblib.load(self.model_dir / "threat_classifier.pkl")
        except FileNotFoundError:
            print("   ⚠️ threat_classifier.pkl not found, multi-class disabled")
        
        # Preprocessing artifacts
        self.scaler = joblib.load(self.model_dir / "scaler.pkl")
        self.encoders = joblib.load(self.model_dir / "label_encoders.pkl")
        self.feature_names = joblib.load(self.model_dir / "feature_names.pkl")
        
        print(f"   ✅ Loaded ensemble: {type(self.ensemble_model).__name__}")
        print(f"   ✅ Loaded individual models: RF, XGB, LGBM")
        print(f"   ✅ Loaded scaler, encoders, {len(self.feature_names)} feature names")
        if self.threat_classifier:
            print(f"   ✅ Loaded threat classifier: {type(self.threat_classifier).__name__}")
    
    def preprocess_flow(self, flow_dict: Dict[str, Any]) -> np.ndarray:
        """
        Convert nfstream flow dict to model input vector.
        
        Maps nfstream features to our trained feature space (NSL-KDD 41 features).
        """
        # Create feature vector matching training feature order
        feature_vector = []
        
        for fname in self.feature_names:
            val = self._map_flow_feature(fname, flow_dict)
            
            # Apply label encoder for categorical features
            if fname in self.encoders:
                try:
                    val = self.encoders[fname].transform([str(val)])[0]
                except ValueError:
                    # Unseen category - use most common (0)
                    val = 0
                except Exception:
                    val = 0
            
            feature_vector.append(float(val) if val is not None else 0.0)
        
        arr = np.array(feature_vector).reshape(1, -1)
        return self.scaler.transform(arr)
    
    def _map_flow_feature(self, feature_name: str, flow: Dict[str, Any]) -> Any:
        """
        Map nfstream flow attributes to NSL-KDD feature names.
        """
        # Direct mappings
        direct_map = {
            'duration': flow.get('bidirectional_duration_ms', 0) / 1000.0,  # ms to seconds
            'protocol_type': flow.get('protocol_name', 'tcp').lower(),
            'service': flow.get('application_name', 'other').lower(),
            'flag': self._map_tcp_state(flow.get('tcp_state', 'OTH')),
            'src_bytes': flow.get('src2dst_bytes', 0),
            'dst_bytes': flow.get('dst2src_bytes', 0),
            'land': 1 if flow.get('src_ip') == flow.get('dst_ip') else 0,
            'wrong_fragment': flow.get('src2dst_retransmission_packets', 0),
            'urgent': 0,  # Not directly available
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 1,  # Will be computed by connection tracker
            'srv_count': 1,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
        }
        
        if feature_name in direct_map:
            return direct_map[feature_name]
        
        return 0
    
    def _map_tcp_state(self, nfstream_state: str) -> str:
        """Map nfstream TCP state to NSL-KDD flag values."""
        state_map = {
            'SYN': 'S0',
            'SYNACK': 'S1',
            'ESTABLISHED': 'SF',
            'FIN': 'SF',
            'RST': 'REJ',
            'RSTO': 'REJ',
            'TIME_WAIT': 'SF',
            'CLOSE_WAIT': 'SF',
            'LAST_ACK': 'SF',
            'CLOSING': 'SF',
        }
        return state_map.get(nfstream_state, 'OTH')
    
    def predict(self, flow_dict: Dict[str, Any]) -> PredictionResult:
        """
        Predict anomaly for a single flow.
        
        Returns PredictionResult with anomaly detection and threat classification.
        """
        # Preprocess
        X = self.preprocess_flow(flow_dict)
        
        # Ensemble prediction (binary anomaly)
        ensemble_proba = self.ensemble_model.predict_proba(X)[0]
        anomaly_idx = list(self.ensemble_model.classes_).index(1)
        anomaly_confidence = float(ensemble_proba[anomaly_idx])
        is_anomaly = anomaly_confidence >= self.threshold
        
        # Determine threat type
        threat_type = "anomaly" if is_anomaly else "normal"
        threat_category = "normal"
        
        # Multi-class threat classification (if attack detected)
        if is_anomaly and self.threat_classifier:
            try:
                threat_type = self.threat_classifier.predict(X)[0]
                threat_category = self.ATTACK_CATEGORIES.get(threat_type, 'unknown')
            except Exception:
                threat_type = "anomaly"
                threat_category = "unknown"
        
        # Extract key flow features for alerting
        key_features = {
            'src_ip': flow_dict.get('src_ip', 'N/A'),
            'dst_ip': flow_dict.get('dst_ip', 'N/A'),
            'src_port': flow_dict.get('src_port', 'N/A'),
            'dst_port': flow_dict.get('dst_port', 'N/A'),
            'protocol': flow_dict.get('protocol_name', 'N/A'),
            'bytes_total': flow_dict.get('bidirectional_bytes', 0),
            'packets_total': flow_dict.get('bidirectional_packets', 0),
            'duration_ms': flow_dict.get('bidirectional_duration_ms', 0),
        }
        
        return PredictionResult(
            is_anomaly=is_anomaly,
            confidence=anomaly_confidence,
            threat_type=threat_type,
            threat_category=threat_category,
            model_used="ensemble",
            flow_features=key_features
        )
    
    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[PredictionResult]:
        """Predict anomalies for multiple flows (more efficient)."""
        results = []
        for flow in flows:
            results.append(self.predict(flow))
        return results
    
    def update_threshold(self, new_threshold: float):
        """Update anomaly detection threshold."""
        self.threshold = max(0.0, min(1.0, new_threshold))
        print(f"🔧 Threshold updated to {self.threshold:.2f}")


def create_inference_engine(model_dir: str = None, threshold: float = 0.6) -> InferenceEngine:
    """Factory function to create inference engine."""
    model_path = Path(model_dir) if model_dir else None
    return InferenceEngine(model_path, threshold)


if __name__ == "__main__":
    # Test the inference engine
    engine = create_inference_engine()
    
    # Test with a sample flow (simulated)
    test_flow = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 54321,
        'dst_port': 80,
        'protocol_name': 'tcp',
        'tcp_state': 'ESTABLISHED',
        'application_name': 'http',
        'bidirectional_bytes': 1024,
        'bidirectional_packets': 10,
        'bidirectional_duration_ms': 500,
        'src2dst_bytes': 512,
        'dst2src_bytes': 512,
        'src2dst_packets': 5,
        'dst2src_packets': 5,
    }
    
    result = engine.predict(test_flow)
    print(f"\n🧪 Test prediction:")
    print(f"   Anomaly: {result.is_anomaly}")
    print(f"   Confidence: {result.confidence:.4f}")
    print(f"   Threat type: {result.threat_type}")
    print(f"   Threat category: {result.threat_category}")
    print(f"   Model: {result.model_used}")
    print(f"   Flow features: {result.flow_features}")