"""
PALADIN - Inference Time Measurement
File: log_pipeline/consumer/training/measure_inference_time.py

Measures the inference time of the ensemble predictor
"""

import sys
import time
import numpy as np
import pandas as pd
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path('/app/log_pipeline/consumer/training')))

from ensemble_predictor import get_ensemble

print("="*70)
print("⏱️  PALADIN INFERENCE TIME MEASUREMENT")
print("="*70)

# Load test data
print("\n📥 Loading test data...")
test_df = pd.read_csv('/app/data/cic_ids_2017/processed/test_balanced.csv')
X_test = test_df.drop('label', axis=1)

print(f"✅ Loaded {len(X_test):,} test samples")

# Initialize ensemble
print("\n🔄 Initializing ensemble...")
ensemble = get_ensemble()

# ============================================================================
# SINGLE PREDICTION TIMING (Microseconds)
# ============================================================================

print("\n" + "="*70)
print("🔬 SINGLE PREDICTION TIMING")
print("="*70)

# Prepare a single sample as a log_data dict
sample_features = X_test.iloc[0].to_dict()

# Create a realistic log_data dict
log_data = {
    'destination_port': int(sample_features.get('destination_port', 80)),
    'protocol': 'tcp',
    'duration': float(sample_features.get('flow_duration', 1.0)),
    'packets': int(sample_features.get('total_fwd_packets', 10)),
    'service': 'ssh',
    'message': 'login attempt',
    'src_ip': '192.168.1.100',
    'timestamp': '2024-12-06T10:00:00Z'
}

# Warm up (first call loads models into cache)
print("\n🔥 Warming up (first prediction)...")
_ = ensemble.predict(log_data.copy())

# Measure single prediction (100 runs for accuracy)
print("\n📊 Measuring single prediction time (100 iterations)...")

times_us = []
for i in range(100):
    start = time.perf_counter()
    _ = ensemble.predict(log_data.copy())
    end = time.perf_counter()
    times_us.append((end - start) * 1e6)  # Convert to microseconds

# Statistics
mean_time = np.mean(times_us)
std_time = np.std(times_us)
min_time = np.min(times_us)
max_time = np.max(times_us)
median_time = np.median(times_us)

print(f"\n📈 Results (100 predictions):")
print(f"   Mean:     {mean_time:>8.2f} μs ({mean_time/1000:.3f} ms)")
print(f"   Median:   {median_time:>8.2f} μs ({median_time/1000:.3f} ms)")
print(f"   Std Dev:  {std_time:>8.2f} μs")
print(f"   Min:      {min_time:>8.2f} μs")
print(f"   Max:      {max_time:>8.2f} μs")

# ============================================================================
# BATCH PREDICTION TIMING (Throughput)
# ============================================================================

print("\n" + "="*70)
print("📦 BATCH PREDICTION TIMING")
print("="*70)

batch_sizes = [10, 100, 1000, 5000]

for batch_size in batch_sizes:
    if batch_size > len(X_test):
        continue
    
    print(f"\n🔄 Processing {batch_size:,} samples...")
    
    # Create batch of log_data dicts
    batch_logs = []
    for idx in range(batch_size):
        sample = X_test.iloc[idx].to_dict()
        log = {
            'destination_port': int(sample.get('destination_port', 80)),
            'protocol': 'tcp',
            'duration': float(sample.get('flow_duration', 1.0)),
            'packets': int(sample.get('total_fwd_packets', 10)),
            'service': 'ssh',
            'message': 'login attempt',
            'src_ip': f'192.168.1.{idx % 255}',
            'timestamp': '2024-12-06T10:00:00Z'
        }
        batch_logs.append(log)
    
    # Time batch processing
    start = time.perf_counter()
    for log in batch_logs:
        _ = ensemble.predict(log)
    end = time.perf_counter()
    
    total_time = (end - start) * 1000  # milliseconds
    avg_per_sample = (total_time / batch_size) * 1000  # microseconds
    throughput = batch_size / (end - start)  # predictions per second
    
    print(f"   Total time:      {total_time:>10.2f} ms")
    print(f"   Avg per sample:  {avg_per_sample:>10.2f} μs")
    print(f"   Throughput:      {throughput:>10.2f} predictions/sec")

# ============================================================================
# COMPONENT-LEVEL TIMING
# ============================================================================

print("\n" + "="*70)
print("🔍 COMPONENT-LEVEL TIMING")
print("="*70)

# Time each component separately
log_data = {
    'destination_port': 22,
    'protocol': 'tcp',
    'duration': 5.0,
    'packets': 100,
    'service': 'ssh',
    'message': 'failed login attempt',
    'src_ip': '192.168.1.100',
    'timestamp': '2024-12-06T10:00:00Z',
    'eventid': 'login.failed'
}

print("\n📊 Timing individual components (100 iterations each)...")

# 1. Feature extraction (basic)
times_feature_basic = []
for _ in range(100):
    start = time.perf_counter()
    _ = ensemble.extract_features_basic(log_data)
    times_feature_basic.append((time.perf_counter() - start) * 1e6)

print(f"\n1️⃣  Basic Feature Extraction:")
print(f"   Mean: {np.mean(times_feature_basic):>8.2f} μs")

# 2. Feature extraction (advanced)
times_feature_adv = []
for _ in range(100):
    start = time.perf_counter()
    _ = ensemble.extract_features_advanced(log_data)
    times_feature_adv.append((time.perf_counter() - start) * 1e6)

print(f"\n2️⃣  Advanced Feature Extraction:")
print(f"   Mean: {np.mean(times_feature_adv):>8.2f} μs")

# 3. Unsupervised prediction
times_unsup = []
for _ in range(100):
    start = time.perf_counter()
    _ = ensemble.predict_unsupervised(log_data)
    times_unsup.append((time.perf_counter() - start) * 1e6)

print(f"\n3️⃣  Unsupervised Prediction (Isolation Forest):")
print(f"   Mean: {np.mean(times_unsup):>8.2f} μs")

# 4. Supervised prediction
times_sup = []
for _ in range(100):
    start = time.perf_counter()
    _ = ensemble.predict_supervised(log_data)
    times_sup.append((time.perf_counter() - start) * 1e6)

print(f"\n4️⃣  Supervised Prediction (RF + XGBoost):")
print(f"   Mean: {np.mean(times_sup):>8.2f} μs")

# 5. MITRE mapping (if enabled)
if ensemble.mitre_enabled:
    times_mitre = []
    for _ in range(100):
        start = time.perf_counter()
        _ = ensemble.mitre_mapper.map_attack('BRUTE_FORCE', 0.95)
        times_mitre.append((time.perf_counter() - start) * 1e6)
    
    print(f"\n5️⃣  MITRE ATT&CK Mapping:")
    print(f"   Mean: {np.mean(times_mitre):>8.2f} μs")

# 6. Full prediction (all components)
times_full = []
for _ in range(100):
    start = time.perf_counter()
    _ = ensemble.predict(log_data.copy())
    times_full.append((time.perf_counter() - start) * 1e6)

print(f"\n6️⃣  Full Prediction Pipeline:")
print(f"   Mean: {np.mean(times_full):>8.2f} μs")
print(f"   Breakdown:")
print(f"     Feature Extraction: {np.mean(times_feature_adv):>8.2f} μs ({np.mean(times_feature_adv)/np.mean(times_full)*100:>5.1f}%)")
print(f"     Unsupervised:       {np.mean(times_unsup):>8.2f} μs ({np.mean(times_unsup)/np.mean(times_full)*100:>5.1f}%)")
print(f"     Supervised:         {np.mean(times_sup):>8.2f} μs ({np.mean(times_sup)/np.mean(times_full)*100:>5.1f}%)")
if ensemble.mitre_enabled:
    print(f"     MITRE Mapping:      {np.mean(times_mitre):>8.2f} μs ({np.mean(times_mitre)/np.mean(times_full)*100:>5.1f}%)")

# ============================================================================
# COMPARISON TO HONEYTWIN PAPER
# ============================================================================

print("\n" + "="*70)
print("📊 COMPARISON TO HONEYTWIN (2024)")
print("="*70)

honeytwin_inference = 0.035  # microseconds (from paper)

print(f"\nHoneyTwin Paper:")
print(f"   Inference Time: {honeytwin_inference:>8.3f} μs")
print(f"   Features:       6 packet-level")
print(f"   Classifier:     Decision Tree")

print(f"\nPALADIN (Your System):")
print(f"   Inference Time: {mean_time:>8.2f} μs")
print(f"   Difference:     {mean_time - honeytwin_inference:>+8.2f} μs ({((mean_time/honeytwin_inference)-1)*100:>+6.1f}%)")
print(f"   Features:       12 flow-level")
print(f"   Classifier:     Ensemble (RF + XGB)")

if mean_time < 100:
    status = "✅ EXCELLENT"
elif mean_time < 1000:
    status = "✅ GOOD"
elif mean_time < 10000:
    status = "⚠️  ACCEPTABLE"
else:
    status = "❌ SLOW"

print(f"\n   Status: {status}")

# ============================================================================
# REAL-TIME PERFORMANCE ESTIMATE
# ============================================================================

print("\n" + "="*70)
print("🚀 REAL-TIME PERFORMANCE ESTIMATE")
print("="*70)

predictions_per_sec = 1e6 / mean_time  # 1 million μs per second

print(f"\nMaximum Throughput:")
print(f"   {predictions_per_sec:>10.0f} predictions/second")
print(f"   {predictions_per_sec*60:>10.0f} predictions/minute")
print(f"   {predictions_per_sec*3600:>10.0f} predictions/hour")

print(f"\nTypical Honeypot Traffic:")
print(f"   Assume: 100 attack attempts/minute")
print(f"   Required throughput: {100/60:.2f} predictions/second")
print(f"   System capacity: {predictions_per_sec:.0f} predictions/second")
print(f"   Overhead margin: {(predictions_per_sec/(100/60)):.0f}x")

if predictions_per_sec > 1000:
    print(f"\n   ✅ System can easily handle real-time traffic")
else:
    print(f"\n   ⚠️  System may struggle with high-volume attacks")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*70)
print("✅ MEASUREMENT COMPLETE")
print("="*70)

print(f"\n📊 Key Metrics for Presentation:")
print(f"   Average Inference Time:  {mean_time:>.2f} μs ({mean_time/1000:.3f} ms)")
print(f"   Maximum Throughput:      {predictions_per_sec:>,.0f} predictions/sec")
print(f"   Suitable for Real-time:  {'Yes ✅' if predictions_per_sec > 1000 else 'No ❌'}")

print(f"\n💾 Save these numbers for your presentation!")