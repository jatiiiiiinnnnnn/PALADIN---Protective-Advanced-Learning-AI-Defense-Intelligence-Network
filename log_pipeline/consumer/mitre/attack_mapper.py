"""
MITRE ATT&CK Mapper for PALADIN
Maps detected network attacks to MITRE ATT&CK framework
"""

import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class MITREAttackMapper:
    """Maps detected attacks to MITRE ATT&CK tactics and techniques"""
    
    def __init__(self, mitre_matrix_path: str = None):
        """
        Initialize MITRE mapper with knowledge base
        
        Args:
            mitre_matrix_path: Path to MITRE ATT&CK matrix JSON file
        """
        if mitre_matrix_path is None:
            # Default path relative to this file
            current_dir = Path(__file__).parent
            mitre_matrix_path = current_dir / "mitre_matrix.json"
        
        self.mitre_matrix_path = mitre_matrix_path
        self.attack_mappings = {}
        self.severity_levels = {}
        self.kill_chain_mapping = {}
        self.attack_indicators = {}
        
        self._load_mitre_matrix()
        
    def _load_mitre_matrix(self):
        """Load MITRE ATT&CK knowledge base from JSON file"""
        try:
            with open(self.mitre_matrix_path, 'r') as f:
                data = json.load(f)
                
            self.attack_mappings = data.get('attack_mappings', {})
            self.severity_levels = data.get('severity_levels', {})
            self.kill_chain_mapping = data.get('kill_chain_mapping', {})
            self.attack_indicators = data.get('attack_indicators', {})
            
            logger.info(f"Loaded MITRE matrix with {len(self.attack_mappings)} attack types")
            
        except FileNotFoundError:
            logger.error(f"MITRE matrix file not found: {self.mitre_matrix_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in MITRE matrix: {e}")
            raise
    
    def map_attack(self, attack_type: str, confidence: float = None) -> Dict:
        """
        Map detected attack to MITRE ATT&CK framework
        
        Args:
            attack_type: Type of attack detected (e.g., 'BRUTE_FORCE')
            confidence: ML model confidence score (0-1)
            
        Returns:
            Dictionary with MITRE mapping information
        """
        attack_type = attack_type.upper()
        
        if attack_type not in self.attack_mappings:
            logger.warning(f"Unknown attack type: {attack_type}")
            attack_type = "UNKNOWN_THREAT"
        
        mapping = self.attack_mappings[attack_type]
        severity_info = self.severity_levels.get(mapping['severity'], {})
        
        # Calculate risk score (combines severity + confidence)
        base_score = severity_info.get('score', 3)
        risk_score = base_score
        if confidence is not None:
            # Adjust risk score based on ML confidence
            risk_score = base_score * confidence
        
        result = {
            'attack_type': attack_type,
            'timestamp': datetime.now().isoformat(),
            'confidence': confidence,
            'tactics': mapping.get('tactics', []),
            'techniques': mapping.get('techniques', []),
            'severity': mapping['severity'],
            'severity_info': severity_info,
            'risk_score': round(risk_score, 2),
            'description': mapping.get('description', ''),
            'detection': mapping.get('detection', ''),
            'mitigation': mapping.get('mitigation', ''),
            'indicators': self.attack_indicators.get(attack_type, {}),
            'kill_chain_phase': self._identify_kill_chain_phase(mapping.get('tactics', []))
        }
        
        return result
    
    def _identify_kill_chain_phase(self, tactics: List[str]) -> Optional[str]:
        """
        Identify cyber kill chain phase based on tactics
        
        Args:
            tactics: List of MITRE tactics
            
        Returns:
            Kill chain phase name
        """
        for phase, info in self.kill_chain_mapping.items():
            related_tactics = info.get('related_tactics', [])
            if any(tactic in related_tactics for tactic in tactics):
                return phase
        return None
    
    def format_mitre_output(self, mapping: Dict, detailed: bool = True) -> str:
        """
        Format MITRE mapping as readable text
        
        Args:
            mapping: MITRE mapping dictionary
            detailed: Include detailed information
            
        Returns:
            Formatted text output
        """
        lines = []
        
        # Header
        severity = mapping['severity']
        color_emoji = {
            'INFO': '🟢',
            'LOW': '🔵',
            'MEDIUM': '🟡',
            'HIGH': '🟠',
            'CRITICAL': '🔴'
        }
        emoji = color_emoji.get(severity, '⚪')
        
        lines.append(f"\n{emoji} MITRE ATT&CK MAPPING {emoji}")
        lines.append("=" * 60)
        
        # Basic info
        lines.append(f"Attack Type: {mapping['attack_type']}")
        lines.append(f"Severity: {severity} (Score: {mapping['risk_score']}/5.0)")
        if mapping['confidence']:
            lines.append(f"ML Confidence: {mapping['confidence']*100:.1f}%")
        lines.append(f"Priority: {mapping['severity_info'].get('priority', 'N/A')}")
        lines.append(f"Response Time: {mapping['severity_info'].get('response_time', 'N/A')}")
        
        # Tactics
        if mapping['tactics']:
            lines.append(f"\n🎯 TACTICS:")
            for tactic in mapping['tactics']:
                lines.append(f"   • {tactic}")
        
        # Techniques
        if mapping['techniques']:
            lines.append(f"\n🔧 TECHNIQUES:")
            for technique in mapping['techniques']:
                lines.append(f"   • {technique['id']}: {technique['name']}")
                if detailed and technique.get('sub_techniques'):
                    for sub in technique['sub_techniques']:
                        lines.append(f"      └─ {sub['id']}: {sub['name']}")
        
        # Kill chain phase
        if mapping.get('kill_chain_phase'):
            lines.append(f"\n⚔️  KILL CHAIN PHASE: {mapping['kill_chain_phase']}")
        
        if detailed:
            # Description
            lines.append(f"\n📋 DESCRIPTION:")
            lines.append(f"   {mapping['description']}")
            
            # Detection
            lines.append(f"\n🔍 DETECTION:")
            lines.append(f"   {mapping['detection']}")
            
            # Mitigation
            lines.append(f"\n🛡️  MITIGATION:")
            lines.append(f"   {mapping['mitigation']}")
            
            # Indicators
            if mapping['indicators'].get('iocs'):
                lines.append(f"\n⚠️  INDICATORS OF COMPROMISE:")
                for ioc in mapping['indicators']['iocs'][:5]:  # Show first 5
                    lines.append(f"   • {ioc}")
            
            if mapping['indicators'].get('ttps'):
                lines.append(f"\n🎭 TACTICS, TECHNIQUES & PROCEDURES:")
                for ttp in mapping['indicators']['ttps']:
                    lines.append(f"   • {ttp}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def get_attack_statistics(self, attack_history: List[Dict]) -> Dict:
        """
        Generate statistics from attack history
        
        Args:
            attack_history: List of MITRE mappings
            
        Returns:
            Statistics dictionary
        """
        if not attack_history:
            return {}
        
        stats = {
            'total_attacks': len(attack_history),
            'by_severity': {},
            'by_tactic': {},
            'by_technique': {},
            'by_kill_chain': {},
            'average_risk_score': 0,
            'critical_count': 0,
            'high_count': 0
        }
        
        total_risk = 0
        
        for mapping in attack_history:
            # Count by severity
            severity = mapping['severity']
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Count critical/high
            if severity == 'CRITICAL':
                stats['critical_count'] += 1
            elif severity == 'HIGH':
                stats['high_count'] += 1
            
            # Count by tactic
            for tactic in mapping['tactics']:
                stats['by_tactic'][tactic] = stats['by_tactic'].get(tactic, 0) + 1
            
            # Count by technique
            for technique in mapping['techniques']:
                tech_id = technique['id']
                stats['by_technique'][tech_id] = stats['by_technique'].get(tech_id, 0) + 1
            
            # Count by kill chain phase
            phase = mapping.get('kill_chain_phase')
            if phase:
                stats['by_kill_chain'][phase] = stats['by_kill_chain'].get(phase, 0) + 1
            
            # Sum risk scores
            total_risk += mapping['risk_score']
        
        stats['average_risk_score'] = round(total_risk / len(attack_history), 2)
        
        return stats
    
    def generate_incident_report(self, attack_history: List[Dict]) -> str:
        """
        Generate comprehensive incident report
        
        Args:
            attack_history: List of MITRE mappings
            
        Returns:
            Formatted incident report
        """
        stats = self.get_attack_statistics(attack_history)
        
        report = []
        report.append("\n" + "=" * 70)
        report.append("🚨 PALADIN SECURITY INCIDENT REPORT 🚨")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Analysis Period: {len(attack_history)} attacks detected")
        report.append("")
        
        # Executive Summary
        report.append("📊 EXECUTIVE SUMMARY")
        report.append("-" * 70)
        report.append(f"Total Security Events: {stats['total_attacks']}")
        report.append(f"Critical Threats: {stats['critical_count']}")
        report.append(f"High Priority Threats: {stats['high_count']}")
        report.append(f"Average Risk Score: {stats['average_risk_score']}/5.0")
        report.append("")
        
        # Severity breakdown
        report.append("🎯 THREAT SEVERITY DISTRIBUTION")
        report.append("-" * 70)
        for severity, count in sorted(stats['by_severity'].items(), 
                                      key=lambda x: self.severity_levels[x[0]]['score'], 
                                      reverse=True):
            percentage = (count / stats['total_attacks']) * 100
            report.append(f"{severity:12s}: {count:3d} ({percentage:5.1f}%)")
        report.append("")
        
        # Top tactics
        if stats['by_tactic']:
            report.append("🎯 TOP ATTACK TACTICS")
            report.append("-" * 70)
            sorted_tactics = sorted(stats['by_tactic'].items(), 
                                   key=lambda x: x[1], reverse=True)[:5]
            for tactic, count in sorted_tactics:
                report.append(f"{tactic:30s}: {count:3d} occurrences")
            report.append("")
        
        # Top techniques
        if stats['by_technique']:
            report.append("🔧 TOP ATTACK TECHNIQUES")
            report.append("-" * 70)
            sorted_techniques = sorted(stats['by_technique'].items(), 
                                      key=lambda x: x[1], reverse=True)[:5]
            for tech_id, count in sorted_techniques:
                report.append(f"{tech_id:15s}: {count:3d} occurrences")
            report.append("")
        
        # Kill chain analysis
        if stats['by_kill_chain']:
            report.append("⚔️  CYBER KILL CHAIN ANALYSIS")
            report.append("-" * 70)
            sorted_phases = sorted(stats['by_kill_chain'].items(), 
                                  key=lambda x: self.kill_chain_mapping[x[0]]['phase_number'])
            for phase, count in sorted_phases:
                report.append(f"{phase:25s}: {count:3d} attacks")
            report.append("")
        
        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 70)
        
        if stats['critical_count'] > 0:
            report.append("• IMMEDIATE ACTION: Address critical threats immediately")
        if stats['high_count'] > 3:
            report.append("• HIGH PRIORITY: Investigate high-severity incidents within 1 hour")
        if 'Reconnaissance' in stats['by_kill_chain']:
            report.append("• PREVENTION: Reconnaissance detected - strengthen perimeter defenses")
        if 'Command and Control' in stats['by_kill_chain']:
            report.append("• CONTAINMENT: C2 activity detected - isolate affected systems")
        
        report.append("")
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def create_attack_timeline(self, attack_history: List[Dict]) -> List[Dict]:
        """
        Create timeline of attacks showing progression
        
        Args:
            attack_history: List of MITRE mappings with timestamps
            
        Returns:
            Sorted timeline with kill chain progression
        """
        timeline = []
        
        for mapping in sorted(attack_history, key=lambda x: x['timestamp']):
            timeline.append({
                'timestamp': mapping['timestamp'],
                'attack_type': mapping['attack_type'],
                'severity': mapping['severity'],
                'kill_chain_phase': mapping.get('kill_chain_phase'),
                'tactics': mapping['tactics'],
                'risk_score': mapping['risk_score']
            })
        
        return timeline


if __name__ == "__main__":
    # Test the mapper
    mapper = MITREAttackMapper()
    
    # Test different attack types
    test_attacks = [
        ('BRUTE_FORCE', 0.95),
        ('DOS', 0.88),
        ('PORT_SCAN', 0.76),
        ('WEB_ATTACK', 0.92),
        ('INFILTRATION', 0.99)
    ]
    
    attack_history = []
    
    for attack_type, confidence in test_attacks:
        mapping = mapper.map_attack(attack_type, confidence)
        attack_history.append(mapping)
        print(mapper.format_mitre_output(mapping, detailed=True))
        print("\n")
    
    # Generate report
    print(mapper.generate_incident_report(attack_history))