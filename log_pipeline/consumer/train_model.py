import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
import os

print("🤖 Training improved PALADIN anomaly detection model...")

# Define features: [port, hour_of_day, is_ssh, failed_login, num_attempts]
# Train ONLY on legitimate traffic patterns - NO attacks in training data!

X_train = np.array([
    # HTTP traffic (normal web browsing during business hours)
    [8080, 9, 0, 0, 1],
    [8080, 10, 0, 0, 1],
    [8080, 11, 0, 0, 1],
    [8080, 13, 0, 0, 1],
    [8080, 14, 0, 0, 1],
    [8080, 15, 0, 0, 1],
    [8080, 16, 0, 0, 1],
    [8080, 17, 0, 0, 1],
    
    # FTP traffic (normal file transfers during work hours)
    [2121, 10, 0, 0, 1],
    [2121, 11, 0, 0, 1],
    [2121, 14, 0, 0, 1],
    [2121, 15, 0, 0, 1],
    [2121, 16, 0, 0, 1],
    
    # SMTP traffic (normal email sending)
    [2525, 8, 0, 0, 1],
    [2525, 9, 0, 0, 1],
    [2525, 12, 0, 0, 1],
    [2525, 14, 0, 0, 1],
    [2525, 17, 0, 0, 1],
])

# Train the model - key: contamination must be very low since training data is all normal
model = IsolationForest(
    n_estimators=200,      # More trees for better detection
    contamination=0.001,   # Expect almost no anomalies in training (0.1%)
    random_state=42,
    max_samples='auto',
    bootstrap=False        # Don't bootstrap for small datasets
)
model.fit(X_train)

# Save it
model_filename = '/app/anomaly_detector.pkl'
joblib.dump(model, model_filename)
print(f"✅ Model saved to: {model_filename}")

print("\n" + "="*70)
print("MODEL VALIDATION TESTS")
print("="*70)

# Test normal traffic
print("\n✅ NORMAL TRAFFIC (Should have POSITIVE scores):")
normal_tests = [
    ([8080, 10, 0, 0, 1], "HTTP at 10 AM, no failed login"),
    ([2121, 14, 0, 0, 1], "FTP at 2 PM, no failed login"),
    ([2525, 9, 0, 0, 1], "SMTP at 9 AM, no failed login"),
    ([8080, 15, 0, 0, 1], "HTTP at 3 PM, normal pattern"),
]

for features, description in normal_tests:
    score = model.decision_function([features])[0]
    prediction = model.predict([features])[0]
    status = "✅ NORMAL" if prediction == 1 else "🚨 ANOMALY"
    print(f"  {description:35s} Score: {score:+.4f} → {status}")

# Test anomalous patterns
print("\n🚨 ATTACK PATTERNS (Should have NEGATIVE scores):")
attack_tests = [
    ([2222, 10, 1, 1, 3], "SSH with failed login (port 2222)"),
    ([2222, 3, 1, 1, 3], "SSH at 3 AM (suspicious time)"),
    ([2222, 2, 1, 1, 10], "SSH brute force (10 attempts at 2 AM)"),
    ([8080, 2, 0, 1, 1], "HTTP with failed login at 2 AM"),
    ([2121, 23, 0, 1, 5], "FTP failed login late night"),
    ([2222, 15, 1, 1, 1], "Any SSH failed login (Cowrie trap)"),
    ([2222, 12, 1, 0, 1], "SSH connection (even no failed login)"),
]

for features, description in attack_tests:
    score = model.decision_function([features])[0]
    prediction = model.predict([features])[0]
    status = "🚨 ANOMALY" if prediction == -1 else "❌ MISSED (should be anomaly!)"
    print(f"  {description:35s} Score: {score:+.4f} → {status}")

print("\n" + "="*70)
print("KEY INSIGHT:")
print("  - Normal traffic: ports 8080, 2121, 2525 during business hours")
print("  - Attacks: port 2222 (SSH honeypot), failed logins, odd hours")
print("  - SSH (port 2222) should ALWAYS be anomalous - it's a honeypot!")
print("="*70)