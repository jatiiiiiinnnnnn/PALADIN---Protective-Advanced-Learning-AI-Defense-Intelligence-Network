"""
Test Script for MITRE ATT&CK Integration
Demonstrates the complete MITRE mapping functionality
"""

import numpy as np
from attack_mapper import MITREAttackMapper
import json


def print_section(title):
    """Print formatted section header"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def test_mitre_mapper():
    """Test MITRE attack mapper with various attack types"""
    
    print_section("🎯 TESTING MITRE ATT&CK MAPPER")
    
    # Initialize mapper
    mapper = MITREAttackMapper('mitre_matrix.json')
    
    # Test different attack scenarios
    test_scenarios = [
        {
            'name': 'SSH Brute Force Attack',
            'attack_type': 'BRUTE_FORCE',
            'confidence': 0.947,
            'context': 'Detected multiple failed SSH login attempts from single IP'
        },
        {
            'name': 'DDoS Attack',
            'attack_type': 'DDOS',
            'confidence': 0.892,
            'context': 'High volume traffic from multiple sources detected'
        },
        {
            'name': 'Port Scanning Activity',
            'attack_type': 'PORT_SCAN',
            'confidence': 0.763,
            'context': 'Sequential connection attempts to multiple ports'
        },
        {
            'name': 'SQL Injection Attempt',
            'attack_type': 'WEB_ATTACK',
            'confidence': 0.923,
            'context': 'Malicious SQL patterns in HTTP POST parameters'
        },
        {
            'name': 'Advanced Persistent Threat',
            'attack_type': 'INFILTRATION',
            'confidence': 0.989,
            'context': 'Lateral movement and privilege escalation detected'
        },
        {
            'name': 'Botnet C2 Communication',
            'attack_type': 'BOTNET',
            'confidence': 0.856,
            'context': 'Beaconing behavior and DGA domain queries detected'
        },
        {
            'name': 'Unknown Anomalous Behavior',
            'attack_type': 'UNKNOWN_THREAT',
            'confidence': 0.724,
            'context': 'Novel attack pattern not matching known signatures'
        }
    ]
    
    attack_history = []
    
    for scenario in test_scenarios:
        print_section(f"TEST CASE: {scenario['name']}")
        print(f"Context: {scenario['context']}\n")
        
        # Map attack
        mapping = mapper.map_attack(
            attack_type=scenario['attack_type'],
            confidence=scenario['confidence']
        )
        
        attack_history.append(mapping)
        
        # Display MITRE mapping
        print(mapper.format_mitre_output(mapping, detailed=True))
        
        input("\n[Press ENTER to continue to next test case...]")
    
    return mapper, attack_history


def test_attack_statistics(mapper, attack_history):
    """Test attack statistics generation"""
    
    print_section("📊 ATTACK STATISTICS")
    
    stats = mapper.get_attack_statistics(attack_history)
    
    print(f"Total Attacks Analyzed: {stats['total_attacks']}")
    print(f"Critical Threats: {stats['critical_count']}")
    print(f"High Priority Threats: {stats['high_count']}")
    print(f"Average Risk Score: {stats['average_risk_score']}/5.0")
    
    print("\n🎯 Severity Distribution:")
    for severity, count in sorted(stats['by_severity'].items()):
        percentage = (count / stats['total_attacks']) * 100
        print(f"   {severity:12s}: {count} ({percentage:.1f}%)")
    
    print("\n🎯 Top Attack Tactics:")
    sorted_tactics = sorted(stats['by_tactic'].items(), 
                           key=lambda x: x[1], reverse=True)
    for tactic, count in sorted_tactics:
        print(f"   {tactic:30s}: {count} occurrences")
    
    print("\n🔧 Top Attack Techniques:")
    sorted_techniques = sorted(stats['by_technique'].items(), 
                              key=lambda x: x[1], reverse=True)
    for tech_id, count in sorted_techniques:
        print(f"   {tech_id:15s}: {count} occurrences")
    
    if stats['by_kill_chain']:
        print("\n⚔️  Cyber Kill Chain Distribution:")
        for phase, count in sorted(stats['by_kill_chain'].items()):
            print(f"   {phase:30s}: {count} attacks")


def test_incident_report(mapper, attack_history):
    """Test incident report generation"""
    
    print_section("📋 SECURITY INCIDENT REPORT")
    
    report = mapper.generate_incident_report(attack_history)
    print(report)


def test_attack_timeline(mapper, attack_history):
    """Test attack timeline generation"""
    
    print_section("⏱️  ATTACK TIMELINE")
    
    timeline = mapper.create_attack_timeline(attack_history)
    
    print(f"{'Timestamp':<20} {'Attack Type':<18} {'Severity':<10} {'Kill Chain Phase':<25} {'Risk'}")
    print("-" * 100)
    
    for event in timeline:
        timestamp = event['timestamp'].split('T')[1][:8]  # Just show time
        print(f"{timestamp:<20} {event['attack_type']:<18} {event['severity']:<10} "
              f"{event.get('kill_chain_phase', 'N/A'):<25} {event['risk_score']:.2f}")


def demonstrate_integration():
    """Demonstrate how to integrate with existing ML models"""
    
    print_section("🔌 INTEGRATION EXAMPLE")
    
    print("""
This is how you integrate MITRE mapping with your existing models:

1. Import the enhanced predictor:
   
   from mitre_enhanced_predictor import create_enhanced_predictor
   
2. Create enhanced predictor with your trained models:
   
   enhanced_predictor = create_enhanced_predictor(
       isolation_forest=iso_forest_model,
       random_forest=rf_model,
       scaler=scaler,
       mitre_matrix_path='mitre_matrix.json'
   )
   
3. Use it for predictions with MITRE mapping:
   
   result = enhanced_predictor.predict(features)
   print(enhanced_predictor.format_prediction_output(result, detailed=True))
   
4. Generate reports:
   
   # After processing multiple predictions
   print(enhanced_predictor.get_attack_summary())
   print(enhanced_predictor.generate_report())

5. The enhanced predictor automatically:
   - Maps all detected attacks to MITRE framework
   - Tracks attack history
   - Provides rich context for each detection
   - Generates comprehensive security reports
    """)


def show_mitre_matrix_structure():
    """Show the structure of MITRE matrix"""
    
    print_section("📚 MITRE MATRIX STRUCTURE")
    
    print("""
The MITRE matrix JSON contains:

1. attack_mappings: Maps each attack type to:
   - MITRE Tactics (e.g., "Initial Access", "Credential Access")
   - MITRE Techniques (e.g., "T1110 - Brute Force")
   - Sub-techniques (e.g., "T1110.001 - Password Guessing")
   - Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
   - Detection methods
   - Mitigation strategies

2. severity_levels: Defines severity scoring:
   - Score (1-5)
   - Priority (P0-P4)
   - Response time requirements
   - Color coding

3. kill_chain_mapping: Maps to Cyber Kill Chain phases:
   - Reconnaissance
   - Weaponization
   - Delivery
   - Exploitation
   - Installation
   - Command and Control
   - Actions on Objectives

4. attack_indicators: Lists IOCs and TTPs for each attack:
   - Indicators of Compromise
   - Tactics, Techniques & Procedures
   - Behavioral patterns
    """)
    
    # Show example mapping
    mapper = MITREAttackMapper('mitre_matrix.json')
    
    print("\nExample: BRUTE_FORCE mapping structure:")
    brute_force = mapper.attack_mappings['BRUTE_FORCE']
    print(json.dumps(brute_force, indent=2))


def main():
    """Main test function"""
    
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║           🛡️  PALADIN MITRE ATT&CK INTEGRATION TEST  🛡️            ║
║                                                                   ║
║  Testing MITRE ATT&CK mapping capabilities for the PALADIN       ║
║  network intrusion detection system.                              ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Test 1: MITRE Mapper
        mapper, attack_history = test_mitre_mapper()
        
        input("\n[Press ENTER to continue to statistics...]")
        
        # Test 2: Statistics
        test_attack_statistics(mapper, attack_history)
        
        input("\n[Press ENTER to continue to incident report...]")
        
        # Test 3: Incident Report
        test_incident_report(mapper, attack_history)
        
        input("\n[Press ENTER to continue to attack timeline...]")
        
        # Test 4: Timeline
        test_attack_timeline(mapper, attack_history)
        
        input("\n[Press ENTER to see integration example...]")
        
        # Test 5: Integration Guide
        demonstrate_integration()
        
        input("\n[Press ENTER to see MITRE matrix structure...]")
        
        # Test 6: Matrix Structure
        show_mitre_matrix_structure()
        
        print_section("✅ ALL TESTS COMPLETED SUCCESSFULLY")
        
        print("""
Next Steps:
1. ✅ MITRE ATT&CK mapping is ready to use
2. 🔌 Integrate with your Kafka consumer
3. 📊 Start collecting attack intelligence
4. 📈 Generate security reports
5. 🎯 Use MITRE data for threat hunting

The MITRE integration enhances your PALADIN system by:
- Providing industry-standard attack classification
- Enabling better security reporting
- Supporting threat intelligence sharing
- Making your research more academically rigorous
- Facilitating comparison with commercial systems
        """)
        
    except FileNotFoundError:
        print("\n❌ ERROR: mitre_matrix.json not found!")
        print("Make sure mitre_matrix.json is in the same directory as this script.")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()