"""
LSTM Sequence Analyzer for PALADIN
Tracks attacker behavior over time and detects multi-stage attacks

File: log_pipeline/consumer/training/lstm_analyzer.py
"""

from pathlib import Path
import numpy as np
import pickle
from collections import deque, defaultdict
from datetime import datetime, timedelta, timezone
import logging

logger = logging.getLogger(__name__)


class AttackSequence:
    """Represents a sequence of attacks from a single source"""
    
    def __init__(self, source_ip, max_length=10, time_window=3600):
        """
        Initialize attack sequence
        
        Args:
            source_ip: Source IP address
            max_length: Maximum sequence length to track
            time_window: Time window in seconds (default 1 hour)
        """
        self.source_ip = source_ip
        self.max_length = max_length
        self.time_window = time_window
        
        # Attack sequence data
        self.attacks = deque(maxlen=max_length)
        self.timestamps = deque(maxlen=max_length)
        self.services = deque(maxlen=max_length)
        self.ports = deque(maxlen=max_length)
        
        # Sequence statistics
        self.first_seen = None
        self.last_seen = None
        self.total_attacks = 0
        self.attack_types_count = defaultdict(int)
        
    def add_attack(self, attack_type, timestamp, service=None, port=None):
        """Add attack to sequence"""
        # Ensure timestamp is UTC aware
        if timestamp.endswith('Z'):
             timestamp = timestamp.replace('Z', '+00:00')
        
        current_time = datetime.fromisoformat(timestamp)
        
        # If the log didn't have a timezone, force it to UTC
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        
        self.last_seen = current_time
        self.total_attacks += 1
        
        self.attacks.append(attack_type)
        self.timestamps.append(current_time)
        self.services.append(service)
        self.ports.append(port)
        self.attack_types_count[attack_type] += 1
        
        # Clean old attacks outside time window
        self._clean_old_attacks()
    
    def _clean_old_attacks(self):
        """Remove attacks outside time window"""
        if not self.timestamps:
            return
        
        cutoff_time = self.last_seen - timedelta(seconds=self.time_window)
        
        while self.timestamps and self.timestamps[0] < cutoff_time:
            self.timestamps.popleft()
            self.attacks.popleft()
            self.services.popleft()
            self.ports.popleft()
    
    def get_sequence_vector(self, attack_encoder):
        """Get numerical representation of attack sequence"""
        if not self.attacks:
            return []
        
        # Convert attack types to numbers
        sequence = []
        for attack in self.attacks:
            encoded = attack_encoder.get(attack, attack_encoder.get('UNKNOWN', 0))
            sequence.append(encoded)
        
        return sequence
    
    def get_time_deltas(self):
        """Get time intervals between attacks (in seconds)"""
        if len(self.timestamps) < 2:
            return []
        
        deltas = []
        for i in range(1, len(self.timestamps)):
            delta = (self.timestamps[i] - self.timestamps[i-1]).total_seconds()
            deltas.append(delta)
        
        return deltas
    
    def get_statistics(self):
        """Get sequence statistics with Safe Defaults"""
        # 1. Define safe defaults (Prevent KeyErrors)
        stats = {
            'source_ip': self.source_ip,
            'sequence_length': len(self.attacks) if self.attacks else 0,
            'total_attacks': self.total_attacks,
            'duration_seconds': 0.0,
            'attack_rate': 0.0,
            'unique_attack_types': len(self.attack_types_count),
            'attack_distribution': dict(self.attack_types_count),
            'recent_sequence': list(self.attacks)[-5:] if self.attacks else [],
            'first_seen': None,
            'last_seen': None
        }

        # 2. If data is invalid, return defaults immediately
        if not self.attacks or self.first_seen is None or self.last_seen is None:
            return stats
            
        # 3. Calculate real stats if data is good
        try:
            duration = (self.last_seen - self.first_seen).total_seconds()
            stats['duration_seconds'] = duration
            stats['attack_rate'] = len(self.attacks) / max(duration, 1.0)
            stats['first_seen'] = self.first_seen.isoformat()
            stats['last_seen'] = self.last_seen.isoformat()
        except Exception as e:
            # If math fails (e.g. timezone mismatch), just keep defaults
            print(f"[!] Stats calculation error: {e}")
            
        return stats


class LSTMSequenceAnalyzer:
    """
    LSTM-based sequence analyzer for detecting attack patterns
    """
    
    def __init__(self, sequence_length=10, time_window=3600):
        """
        Initialize LSTM analyzer
        
        Args:
            sequence_length: Maximum sequence length to track
            time_window: Time window for sequence tracking (seconds)
        """
        self.sequence_length = sequence_length
        self.time_window = time_window
        
        # Track sequences per source IP
        self.active_sequences = {}
        
        # Attack type encoding
        self.attack_encoder = {
            'NORMAL': 0,
            'UNKNOWN_THREAT': 1,
            'BRUTE_FORCE': 2,
            'DOS': 3,
            'DDOS': 4,
            'PORT_SCAN': 5,
            'WEB_ATTACK': 6,
            'BOTNET': 7,
            'INFILTRATION': 8,
            'HEARTBLEED': 9
        }
        
        # Known attack patterns (attack chains)
        self.attack_patterns = self._define_attack_patterns()
        
        # Campaign tracking
        self.campaigns = defaultdict(list)
        
        logger.info("LSTM Sequence Analyzer initialized")
        logger.info(f"  Sequence length: {sequence_length}")
        logger.info(f"  Time window: {time_window}s ({time_window/3600:.1f} hours)")

        self.state_file = Path('/app/data/lstm_state.pkl') # Persist here
        self._load_state()
    
    def _save_state(self):
        """Save active sequences to disk"""
        try:
            with open(self.state_file, 'wb') as f:
                pickle.dump(self.active_sequences, f)
        except Exception as e:
            print(f"Error saving state: {e}")

    def _load_state(self):
        """Load sequences from disk"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'rb') as f:
                    self.active_sequences = pickle.load(f)
                print(f"   [LSTM] Loaded {len(self.active_sequences)} active sessions from disk")
            except Exception as e:
                print(f"   [LSTM] Error loading state: {e}")
    
    def _define_attack_patterns(self):
        """Define known multi-stage attack patterns"""
        return {
            'reconnaissance_to_attack': {
                'pattern': ['PORT_SCAN', 'BRUTE_FORCE'],
                'description': 'Reconnaissance followed by credential attack',
                'severity': 'HIGH',
                'kill_chain': ['Reconnaissance', 'Initial Access']
            },
            'reconnaissance_to_infiltration': {
                'pattern': ['PORT_SCAN', 'WEB_ATTACK', 'INFILTRATION'],
                'description': 'Full attack chain from recon to infiltration',
                'severity': 'CRITICAL',
                'kill_chain': ['Reconnaissance', 'Initial Access', 'Persistence']
            },
            'persistent_brute_force': {
                'pattern': ['BRUTE_FORCE', 'BRUTE_FORCE', 'BRUTE_FORCE'],
                'description': 'Sustained credential attack campaign',
                'severity': 'HIGH',
                'kill_chain': ['Initial Access']
            },
            'distributed_attack': {
                'pattern': ['DOS', 'DDOS'],
                'description': 'Escalation from single to distributed DoS',
                'severity': 'CRITICAL',
                'kill_chain': ['Impact']
            },
            'botnet_activity': {
                'pattern': ['BOTNET', 'DOS'],
                'description': 'Botnet conducting attacks',
                'severity': 'CRITICAL',
                'kill_chain': ['Command and Control', 'Impact']
            },
            'web_exploitation': {
                'pattern': ['WEB_ATTACK', 'WEB_ATTACK', 'INFILTRATION'],
                'description': 'Web exploitation leading to infiltration',
                'severity': 'CRITICAL',
                'kill_chain': ['Initial Access', 'Persistence']
            }
        }
    
    def process_attack(self, log_data, attack_type, timestamp):
        """
        Process new attack and update sequence
        
        Args:
            log_data: Raw log data
            attack_type: Detected attack type
            timestamp: Attack timestamp
            
        Returns:
            Analysis results
        """
        # Extract source IP
        source_ip = log_data.get('src_ip', log_data.get('source_ip', 'unknown'))
        service = log_data.get('service', 'unknown')
        port = log_data.get('destination_port', 0)
        
        # Skip normal traffic
        if attack_type == 'NORMAL':
            return None
        
        # Get or create sequence for this IP
        if source_ip not in self.active_sequences:
            self.active_sequences[source_ip] = AttackSequence(
                source_ip, 
                max_length=self.sequence_length,
                time_window=self.time_window
            )
        
        sequence = self.active_sequences[source_ip]
        sequence.add_attack(attack_type, timestamp, service, port)
        
        # Analyze sequence
        analysis = self._analyze_sequence(sequence)
        
        # Clean up old sequences
        self._cleanup_old_sequences()
        self._save_state()
        
        return analysis
    
    def _analyze_sequence(self, sequence):
        """Analyze attack sequence for patterns"""
        analysis = {
            'sequence_detected': True,
            'source_ip': sequence.source_ip,
            'sequence_length': len(sequence.attacks),
            'statistics': sequence.get_statistics(),
            'patterns_detected': [],
            'threat_level': 'MEDIUM',
            'behavioral_score': 0.0,
            'recommendations': []
        }
        
        if len(sequence.attacks) < 2:
            return analysis
        
        # Check for known attack patterns
        recent_attacks = list(sequence.attacks)
        
        for pattern_name, pattern_info in self.attack_patterns.items():
            if self._matches_pattern(recent_attacks, pattern_info['pattern']):
                analysis['patterns_detected'].append({
                    'name': pattern_name,
                    'description': pattern_info['description'],
                    'severity': pattern_info['severity'],
                    'kill_chain': pattern_info['kill_chain']
                })
        
        # Calculate behavioral threat score
        analysis['behavioral_score'] = self._calculate_threat_score(sequence)
        
        # Determine overall threat level
        analysis['threat_level'] = self._determine_threat_level(
            sequence, 
            analysis['patterns_detected'],
            analysis['behavioral_score']
        )
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(
            sequence,
            analysis['patterns_detected']
        )
        
        return analysis
    
    def _matches_pattern(self, attack_sequence, pattern):
        """Check if attack sequence matches a known pattern"""
        if len(attack_sequence) < len(pattern):
            return False
        
        # Check last N attacks match pattern
        recent = attack_sequence[-len(pattern):]
        
        # Exact match
        if recent == pattern:
            return True
        
        # Allow for some flexibility (pattern appears in sequence)
        pattern_str = '->'.join(pattern)
        sequence_str = '->'.join(attack_sequence)
        
        return pattern_str in sequence_str
    
    def _calculate_threat_score(self, sequence):
        """Calculate behavioral threat score (0-1)"""
        score = 0.0
        
        # Factor 1: Sequence length (longer = more suspicious)
        length_score = min(len(sequence.attacks) / 10.0, 1.0)
        score += length_score * 0.3
        
        # Factor 2: Attack diversity (more types = more sophisticated)
        diversity_score = min(len(sequence.attack_types_count) / 5.0, 1.0)
        score += diversity_score * 0.2
        
        # Factor 3: Attack rate (faster = more aggressive)
        time_deltas = sequence.get_time_deltas()
        if time_deltas:
            avg_delta = np.mean(time_deltas)
            # Fast attacks (< 60s between) are suspicious
            rate_score = max(0, 1.0 - (avg_delta / 60.0))
            score += rate_score * 0.3
        
        # Factor 4: Critical attack types present
        critical_attacks = ['INFILTRATION', 'BOTNET', 'DDOS', 'HEARTBLEED']
        critical_score = sum(1 for a in sequence.attacks if a in critical_attacks) / max(len(sequence.attacks), 1)
        score += critical_score * 0.2
        
        return min(score, 1.0)
    
    def _determine_threat_level(self, sequence, patterns, behavioral_score):
        """Determine overall threat level"""
        # Check for critical patterns
        for pattern in patterns:
            if pattern['severity'] == 'CRITICAL':
                return 'CRITICAL'
        
        # Check behavioral score
        if behavioral_score > 0.8:
            return 'CRITICAL'
        elif behavioral_score > 0.6:
            return 'HIGH'
        elif behavioral_score > 0.4:
            return 'MEDIUM'
        
        # Check sequence characteristics
        if len(sequence.attacks) >= 5:
            return 'HIGH'
        elif len(sequence.attacks) >= 3:
            return 'MEDIUM'
        
        return 'LOW'
    
    def _generate_recommendations(self, sequence, patterns):
        """Generate security recommendations"""
        recommendations = []
        
        # Based on patterns
        for pattern in patterns:
            if 'reconnaissance' in pattern['name']:
                recommendations.append("Block source IP - active reconnaissance detected")
            if 'infiltration' in pattern['name']:
                recommendations.append("URGENT: Isolate affected systems - infiltration in progress")
            if 'botnet' in pattern['name']:
                recommendations.append("Deploy botnet mitigation - coordinated attack detected")
        
        # Based on sequence characteristics
        if len(sequence.attacks) >= 5:
            recommendations.append("Implement rate limiting for this IP")
        
        if sequence.get_statistics()['attack_rate'] > 0.1:  # > 1 attack per 10 seconds
            recommendations.append("Consider temporary IP ban - high attack rate")
        
        if len(sequence.attack_types_count) >= 3:
            recommendations.append("Alert SOC team - sophisticated multi-vector attack")
        
        return recommendations
    
    def _cleanup_old_sequences(self):
        """Remove inactive sequences"""
        # FIXED: Use UTC to match the log timestamps
        current_time = datetime.now(timezone.utc)
        
        cutoff_time = current_time - timedelta(seconds=self.time_window * 2)
        
        to_remove = []
        for ip, sequence in self.active_sequences.items():
            if sequence.last_seen and sequence.last_seen < cutoff_time:
                to_remove.append(ip)
        
        for ip in to_remove:
            del self.active_sequences[ip]
    
    def get_active_attackers(self):
        """Get list of currently active attackers"""
        return {
            ip: seq.get_statistics() 
            for ip, seq in self.active_sequences.items()
            if len(seq.attacks) > 0
        }
    
    def get_top_attackers(self, n=10):
        """Get top N most active attackers"""
        attackers = []
        for ip, seq in self.active_sequences.items():
            stats = seq.get_statistics()
            stats['threat_score'] = self._calculate_threat_score(seq)
            attackers.append(stats)
        
        # Sort by threat score
        attackers.sort(key=lambda x: x['threat_score'], reverse=True)
        
        return attackers[:n]
    
    def generate_campaign_report(self):
        """Generate report on detected attack campaigns"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_active_attackers': len(self.active_sequences),
            'top_attackers': self.get_top_attackers(5),
            'attack_patterns_detected': [],
            'recommendations': []
        }
        
        # Analyze all active sequences for patterns
        pattern_counts = defaultdict(int)
        
        for seq in self.active_sequences.values():
            analysis = self._analyze_sequence(seq)
            for pattern in analysis['patterns_detected']:
                pattern_counts[pattern['name']] += 1
        
        report['attack_patterns_detected'] = [
            {'pattern': name, 'occurrences': count}
            for name, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        
        # Global recommendations
        if len(self.active_sequences) > 10:
            report['recommendations'].append("ALERT: High number of active attackers - possible coordinated attack")
        
        if pattern_counts:
            report['recommendations'].append("Multiple attack patterns detected - review security posture")
        
        return report


# Singleton instance
_lstm_analyzer = None

def get_lstm_analyzer(sequence_length=10, time_window=3600):
    """Get or create LSTM analyzer instance"""
    global _lstm_analyzer
    if _lstm_analyzer is None:
        _lstm_analyzer = LSTMSequenceAnalyzer(
            sequence_length=sequence_length,
            time_window=time_window
        )
    return _lstm_analyzer