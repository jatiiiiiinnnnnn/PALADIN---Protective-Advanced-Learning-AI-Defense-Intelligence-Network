"""
Enhanced Ensemble Predictor with MITRE ATT&CK Integration
Combines ML predictions with MITRE framework mapping
"""

import numpy as np
import logging
from typing import Dict, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class MITREEnhancedPredictor:
    """
    Ensemble predictor enhanced with MITRE ATT&CK mapping
    Combines Isolation Forest + Random Forest with MITRE intelligence
    """
    
    def __init__(self, isolation_forest, random_forest, scaler, mitre_mapper):
        """
        Initialize enhanced predictor
        
        Args:
            isolation_forest: Trained Isolation Forest model
            random_forest: Trained Random Forest classifier
            scaler: Fitted StandardScaler
            mitre_mapper: MITREAttackMapper instance
        """
        self.isolation_forest = isolation_forest
        self.random_forest = random_forest
        self.scaler = scaler
        self.mitre_mapper = mitre_mapper
        
        # Attack history for tracking
        self.attack_history = []
        
        # Thresholds
        self.anomaly_threshold = -0.15
        self.confidence_threshold = 0.7
        
        logger.info("Initialized MITRE-enhanced ensemble predictor")
    
    def predict(self, features: np.ndarray) -> Dict:
        """
        Predict with full MITRE ATT&CK mapping
        
        Args:
            features: Feature vector (already scaled or raw)
            
        Returns:
            Dictionary with prediction and MITRE mapping
        """
        # Reshape if needed
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Scale features if not already scaled
        try:
            features_scaled = self.scaler.transform(features)
        except:
            features_scaled = features
        
        # 1. Unsupervised detection (Isolation Forest)
        anomaly_score = self.isolation_forest.score_samples(features_scaled)[0]
        is_anomaly = anomaly_score < self.anomaly_threshold
        
        # 2. Supervised classification (Random Forest)
        class_probabilities = self.random_forest.predict_proba(features_scaled)[0]
        predicted_class_idx = np.argmax(class_probabilities)
        predicted_class = self.random_forest.classes_[predicted_class_idx]
        confidence = class_probabilities[predicted_class_idx]
        
        # 3. Ensemble decision
        if is_anomaly and predicted_class != 'NORMAL':
            # Both models agree on attack
            final_prediction = predicted_class
            ensemble_confidence = confidence
            detection_method = "ENSEMBLE"
        elif is_anomaly and predicted_class == 'NORMAL':
            # Only unsupervised detected anomaly
            final_prediction = "UNKNOWN_THREAT"
            ensemble_confidence = abs(anomaly_score)
            detection_method = "UNSUPERVISED"
        elif not is_anomaly and predicted_class != 'NORMAL' and confidence > self.confidence_threshold:
            # Only supervised detected attack
            final_prediction = predicted_class
            ensemble_confidence = confidence
            detection_method = "SUPERVISED"
        else:
            # Normal traffic
            final_prediction = "NORMAL"
            ensemble_confidence = 1.0 - confidence if predicted_class != 'NORMAL' else confidence
            detection_method = "BASELINE"
        
        # 4. MITRE ATT&CK Mapping
        mitre_mapping = None
        if final_prediction != "NORMAL":
            mitre_mapping = self.mitre_mapper.map_attack(
                attack_type=final_prediction,
                confidence=ensemble_confidence
            )
            self.attack_history.append(mitre_mapping)
        
        # 5. Compile results
        result = {
            'timestamp': datetime.now().isoformat(),
            'prediction': final_prediction,
            'confidence': float(ensemble_confidence),
            'detection_method': detection_method,
            'anomaly_score': float(anomaly_score),
            'is_anomaly': bool(is_anomaly),
            'class_probabilities': {
                str(cls): float(prob) 
                for cls, prob in zip(self.random_forest.classes_, class_probabilities)
            },
            'mitre_mapping': mitre_mapping
        }
        
        return result
    
    def format_prediction_output(self, result: Dict, detailed: bool = False) -> str:
        """
        Format prediction with MITRE information
        
        Args:
            result: Prediction result dictionary
            detailed: Include detailed MITRE mapping
            
        Returns:
            Formatted output string
        """
        lines = []
        
        prediction = result['prediction']
        confidence = result['confidence']
        
        # Attack detection header
        if prediction != "NORMAL":
            lines.append(f"\n🚨 ATTACK DETECTED: {prediction}")
            lines.append(f"   Confidence: {confidence*100:.1f}%")
            lines.append(f"   Method: {result['detection_method']}")
            lines.append(f"   Anomaly Score: {result['anomaly_score']:.4f}")
            
            # MITRE information
            if result['mitre_mapping']:
                mapping = result['mitre_mapping']
                
                # Compact MITRE summary
                lines.append(f"\n   🎯 MITRE ATT&CK:")
                
                severity = mapping['severity']
                lines.append(f"      Severity: {severity} (Risk: {mapping['risk_score']}/5.0)")
                
                if mapping['tactics']:
                    tactics_str = ", ".join(mapping['tactics'])
                    lines.append(f"      Tactics: {tactics_str}")
                
                if mapping['techniques']:
                    # Show primary technique
                    primary = mapping['techniques'][0]
                    lines.append(f"      Technique: {primary['id']} - {primary['name']}")
                    
                    # Show sub-techniques if present
                    if primary.get('sub_techniques'):
                        sub = primary['sub_techniques'][0]
                        lines.append(f"         └─ {sub['id']}: {sub['name']}")
                
                if mapping.get('kill_chain_phase'):
                    lines.append(f"      Kill Chain: {mapping['kill_chain_phase']}")
                
                lines.append(f"      Priority: {mapping['severity_info'].get('priority')} "
                           f"(Response: {mapping['severity_info'].get('response_time')})")
                
                # Detailed output if requested
                if detailed:
                    lines.append("\n" + self.mitre_mapper.format_mitre_output(mapping, detailed=True))
        else:
            lines.append(f"\n✅ NORMAL TRAFFIC (Confidence: {confidence*100:.1f}%)")
        
        return "\n".join(lines)
    
    def get_attack_summary(self, window: int = 100) -> str:
        """
        Get summary of recent attacks
        
        Args:
            window: Number of recent attacks to analyze
            
        Returns:
            Summary text
        """
        recent_attacks = self.attack_history[-window:] if len(self.attack_history) > window else self.attack_history
        
        if not recent_attacks:
            return "\n📊 No attacks detected in current session"
        
        stats = self.mitre_mapper.get_attack_statistics(recent_attacks)
        
        summary = [f"\n📊 ATTACK SUMMARY (Last {len(recent_attacks)} attacks)"]
        summary.append("=" * 60)
        summary.append(f"Critical: {stats['critical_count']}")
        summary.append(f"High: {stats['high_count']}")
        summary.append(f"Average Risk: {stats['average_risk_score']}/5.0")
        
        if stats['by_severity']:
            summary.append("\nBy Severity:")
            for sev, count in stats['by_severity'].items():
                summary.append(f"   {sev}: {count}")
        
        if stats['by_tactic']:
            summary.append("\nTop Tactics:")
            sorted_tactics = sorted(stats['by_tactic'].items(), 
                                   key=lambda x: x[1], reverse=True)[:3]
            for tactic, count in sorted_tactics:
                summary.append(f"   {tactic}: {count}")
        
        return "\n".join(summary)
    
    def generate_report(self) -> str:
        """
        Generate full incident report
        
        Returns:
            Formatted report
        """
        if not self.attack_history:
            return "\n📋 No attacks to report"
        
        return self.mitre_mapper.generate_incident_report(self.attack_history)
    
    def clear_history(self):
        """Clear attack history"""
        self.attack_history.clear()
        logger.info("Cleared attack history")


def create_enhanced_predictor(isolation_forest, random_forest, scaler, mitre_matrix_path=None):
    """
    Factory function to create MITRE-enhanced predictor
    
    Args:
        isolation_forest: Trained Isolation Forest
        random_forest: Trained Random Forest
        scaler: Fitted StandardScaler
        mitre_matrix_path: Path to MITRE matrix JSON
        
    Returns:
        MITREEnhancedPredictor instance
    """
    from attack_mapper import MITREAttackMapper
    
    mitre_mapper = MITREAttackMapper(mitre_matrix_path)
    
    return MITREEnhancedPredictor(
        isolation_forest=isolation_forest,
        random_forest=random_forest,
        scaler=scaler,
        mitre_mapper=mitre_mapper
    )


if __name__ == "__main__":
    print("MITRE-Enhanced Predictor Module")
    print("Import this module to use with your trained models")
    print("\nExample usage:")
    print("  from mitre_enhanced_predictor import create_enhanced_predictor")
    print("  predictor = create_enhanced_predictor(iso_forest, rf_model, scaler)")
    print("  result = predictor.predict(features)")
    print("  print(predictor.format_prediction_output(result, detailed=True))")