"""
PALADIN Consumer with MITRE + LSTM Display
File: log_pipeline/consumer/consumer.py

Shows: ML predictions + MITRE intelligence + LSTM sequence analysis
"""

import redis
import json
import time
import sys
from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings('ignore')

# Import ensemble predictor
sys.path.append('/app/training')
from ensemble_predictor import get_ensemble

# Configuration
REDIS_HOST = 'redis'
REDIS_PORT = 6379
QUEUE_NAME = 'honeypot_logs'
ES_HOST = 'elasticsearch'
ES_PORT = 9200

def connect_redis():
    """Connect to Redis"""
    print("[*] Connecting to Redis at redis...")
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping()
        print("✅ [*] Redis connected!")
        return r
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        sys.exit(1)

def connect_es():
    """Connect to Elasticsearch"""
    print("[*] Connecting to Elasticsearch at elasticsearch...")
    try:
        es = Elasticsearch([f'http://{ES_HOST}:{ES_PORT}'])
        if es.ping():
            print("✅ [*] Elasticsearch connected!")
            return es
        else:
            print("⚠️  Elasticsearch not responding")
            return None
    except Exception as e:
        print(f"⚠️  Elasticsearch connection failed: {e}")
        return None

def format_mitre_compact(mitre_data):
    """Format MITRE data for compact console output"""
    if not mitre_data:
        return []
    
    lines = []
    lines.append(f"   🎯 MITRE ATT&CK:")
    
    severity = mitre_data.get('severity', 'UNKNOWN')
    risk_score = mitre_data.get('risk_score', 0)
    priority = mitre_data.get('priority', 'N/A')
    response_time = mitre_data.get('response_time', 'Unknown')
    
    severity_emoji = {
        'INFO': '🟢',
        'LOW': '🔵',
        'MEDIUM': '🟡',
        'HIGH': '🟠',
        'CRITICAL': '🔴'
    }
    emoji = severity_emoji.get(severity, '⚪')
    
    lines.append(f"      {emoji} Severity: {severity} (Risk: {risk_score}/5.0)")
    
    if mitre_data.get('tactics'):
        tactics_str = ', '.join(mitre_data['tactics'])
        lines.append(f"      Tactic: {tactics_str}")
    
    techniques = mitre_data.get('techniques', [])
    if techniques:
        primary = techniques[0]
        tech_str = f"{primary['id']}: {primary['name']}"
        lines.append(f"      Technique: {tech_str}")
        
        if primary.get('sub_techniques'):
            for sub in primary['sub_techniques'][:2]:
                lines.append(f"         └─ {sub['id']}: {sub['name']}")
    
    lines.append(f"      Priority: {priority} | Response: {response_time}")
    
    return lines

def format_lstm_analysis(lstm_data):
    """Format LSTM sequence analysis"""
    if not lstm_data or not lstm_data.get('sequence_detected'):
        return []
    
    lines = []
    lines.append(f"   🔗 SEQUENCE ANALYSIS:")
    
    source_ip = lstm_data.get('source_ip', 'unknown')
    seq_length = lstm_data.get('sequence_length', 0)
    threat_level = lstm_data.get('threat_level', 'LOW')
    behavioral_score = lstm_data.get('behavioral_score', 0.0)
    
    threat_emoji = {
        'LOW': '🟢',
        'MEDIUM': '🟡',
        'HIGH': '🟠',
        'CRITICAL': '🔴'
    }
    emoji = threat_emoji.get(threat_level, '⚪')
    
    lines.append(f"      {emoji} Threat Level: {threat_level} (Score: {behavioral_score:.2f})")
    lines.append(f"      Source: {source_ip} | Attacks: {seq_length}")
    
    stats = lstm_data.get('statistics', {})
    if stats.get('recent_sequence'):
        recent = ' → '.join(stats['recent_sequence'])
        lines.append(f"      Sequence: {recent}")
    
    patterns = lstm_data.get('patterns_detected', [])
    if patterns:
        lines.append(f"      ⚠️  Attack Patterns Detected:")
        for pattern in patterns[:2]:
            lines.append(f"         • {pattern['description']}")
            lines.append(f"           Severity: {pattern['severity']}")
    
    recommendations = lstm_data.get('recommendations', [])
    if recommendations:
        lines.append(f"      💡 Recommendations:")
        for rec in recommendations[:2]:
            lines.append(f"         • {rec}")
    
    return lines

def main():
    """Main consumer loop"""
    r = connect_redis()
    es = connect_es()
    
    print("\n[AI] Initializing PALADIN Ensemble...")
    ensemble = get_ensemble()
    
    print("-" * 60)
    print("🚀 PALADIN Intelligence Consumer ONLINE.")
    print("[*] Waiting for logs in queue: 'honeypot-logs'...")
    print("-" * 60)

    message_count = 0
    attack_count = 0
    sequence_attacks = 0

    while True:
        try:
            message = r.blpop(QUEUE_NAME, timeout=1)
            if not message:
                continue

            message_count += 1
            raw_data = message[1]
            log_data = json.loads(raw_data)
            
            if 'protocol' in log_data and 'service' not in log_data:
                log_data['service'] = log_data['protocol'].upper()
            
            if 'dst_port' in log_data and 'destination_port' not in log_data:
                log_data['destination_port'] = log_data['dst_port']
            
            if log_data.get('service') == 'SSH' and 'destination_port' not in log_data:
                log_data['destination_port'] = 2222
            
            enriched_log = ensemble.predict(log_data)
            
            timestamp = enriched_log.get('timestamp', 'No timestamp')
            service = enriched_log.get('service', 'Unknown')
            port = enriched_log.get('destination_port', 'Unknown')
            
            status = enriched_log.get('ai_final_status', '❓ UNKNOWN')
            attack_type = enriched_log.get('ai_attack_type', 'UNKNOWN')
            confidence = enriched_log.get('ai_confidence', 0.0)
            
            print(f"\n[Received] {timestamp}")
            print(f"   Service: {service} | Port: {port}")
            print(f"   {status}: {attack_type} (Confidence: {confidence*100:.1f}%)")
            
            unsup = enriched_log.get('ai_unsupervised', {})
            sup = enriched_log.get('ai_supervised', {})
            
            if unsup.get('score') is not None:
                print(f"   └─ Anomaly: {unsup['score']:.4f} (Unsupervised)")
            
            if sup.get('attack_type'):
                sup_conf = sup.get('confidence', 0)
                print(f"   └─ Class: {sup['attack_type']} @{sup_conf*100:.1f}% (Supervised)")
            
            mitre_data = enriched_log.get('mitre')
            if mitre_data:
                mitre_lines = format_mitre_compact(mitre_data)
                for line in mitre_lines:
                    print(line)
                
                if attack_type != 'NORMAL':
                    attack_count += 1
            
            lstm_data = enriched_log.get('lstm')
            if lstm_data:
                lstm_lines = format_lstm_analysis(lstm_data)
                for line in lstm_lines:
                    print(line)
                
                if lstm_data.get('sequence_length', 0) >= 2:
                    sequence_attacks += 1

            if es:
                try:
                    es.index(index='honeypot-logs', document=enriched_log)
                except:
                    pass
            
            if message_count % 50 == 0:
                print(f"\n{'='*60}")
                print(f"📊 SUMMARY: {message_count} logs | {attack_count} attacks | {sequence_attacks} sequences")
                
                if ensemble.lstm_enabled:
                    try:
                        top_attackers = ensemble.lstm_analyzer.get_top_attackers(3)
                        if top_attackers:
                            print(f"\n🎯 TOP ATTACKERS:")
                            for i, attacker in enumerate(top_attackers, 1):
                                ip = attacker['source_ip']
                                attacks = attacker['sequence_length']
                                threat = attacker['threat_score']
                                print(f"   {i}. {ip}: {attacks} attacks (Threat: {threat:.2f})")
                    except:
                        pass
                
                print(f"{'='*60}\n")

        except json.JSONDecodeError:
            print(f"[!] JSON decode error")
        except KeyboardInterrupt:
            print(f"\n{'='*60}")
            print("[!] Shutting down consumer.")
            print(f"📊 Final Stats: {message_count} logs | {attack_count} attacks | {sequence_attacks} sequences")
            
            if ensemble.lstm_enabled:
                try:
                    print(f"\n📋 ATTACK CAMPAIGN REPORT:")
                    report = ensemble.lstm_analyzer.generate_campaign_report()
                    print(f"   Active Attackers: {report['total_active_attackers']}")
                    
                    if report['attack_patterns_detected']:
                        print(f"   Patterns Detected:")
                        for pattern in report['attack_patterns_detected'][:3]:
                            print(f"      • {pattern['pattern']}: {pattern['occurrences']} times")
                    
                    if report['recommendations']:
                        print(f"   Recommendations:")
                        for rec in report['recommendations'][:3]:
                            print(f"      • {rec}")
                except:
                    pass
            
            print(f"{'='*60}")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(1)

if __name__ == '__main__':
    main()