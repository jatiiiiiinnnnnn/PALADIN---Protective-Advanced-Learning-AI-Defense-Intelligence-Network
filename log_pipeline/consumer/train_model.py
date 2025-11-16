import joblib
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import os

print("🤖 Training PALADIN anomaly detection model (One-Class SVM)...")

# Define features: [port, is_ssh, failed_login, num_attempts]
# Train ONLY on legitimate traffic - OneClassSVM learns what's "normal"

X_train = np.array([
    # HTTP traffic (normal) - [port, is_ssh, failed_login, attempts]
    [8080, 0, 0, 1],
    [8080, 0, 0, 1],
    [8080, 0, 0, 1],
    [8080, 0, 0, 1],
    [8080, 0, 0, 1],
    [8080, 0, 0, 1],
    [8080, 0, 0, 1],
    [8080, 0, 0, 1],
    
    # FTP traffic (normal)
    [2121, 0, 0, 1],
    [2121, 0, 0, 1],
    [2121, 0, 0, 1],
    [2121, 0, 0, 1],
    [2121, 0, 0, 1],
    
    # SMTP traffic (normal)
    [2525, 0, 0, 1],
    [2525, 0, 0, 1],
    [2525, 0, 0, 1],
    [2525, 0, 0, 1],
])

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)

# Train One-Class SVM (better for anomaly detection with small datasets)
model = OneClassSVM(
    kernel='rbf',       # Radial basis function for non-linear patterns
    gamma='auto',       # Auto-calculate gamma
    nu=0.05            # Expected proportion of outliers (5%)
)
model.fit(X_train_scaled)

# Save both model and scaler
model_filename = '/app/anomaly_detector.pkl'
scaler_filename = '/app/scaler.pkl'

joblib.dump(model, model_filename)
joblib.dump(scaler, scaler_filename)

print(f"✅ Model saved to: {model_filename}")
print(f"✅ Scaler saved to: {scaler_filename}")

print("\n" + "="*70)
print("MODEL VALIDATION TESTS")
print("="*70)

# Test normal traffic
print("\n✅ NORMAL TRAFFIC (Prediction = 1 is normal):")
normal_tests = [
    ([8080, 0, 0, 1], "HTTP normal request"),
    ([2121, 0, 0, 1], "FTP normal transfer"),
    ([2525, 0, 0, 1], "SMTP normal email"),
    ([8080, 0, 0, 1], "HTTP another request"),
]

for features, description in normal_tests:
    features_scaled = scaler.transform([features])
    prediction = model.predict(features_scaled)[0]
    score = model.decision_function(features_scaled)[0]
    status = "✅ NORMAL" if prediction == 1 else "🚨 ANOMALY"
    print(f"  {description:30s} Pred: {prediction:+2d} | Score: {score:+.4f} → {status}")

# Test anomalous patterns
print("\n🚨 ATTACK PATTERNS (Prediction = -1 is anomaly):")
attack_tests = [
    ([2222, 1, 0, 1], "SSH connection (honeypot port)"),
    ([2222, 1, 1, 1], "SSH with failed login"),
    ([2222, 1, 1, 3], "SSH brute force (3 attempts)"),
    ([2222, 1, 1, 10], "SSH scanning (10 attempts)"),
    ([8080, 0, 1, 1], "HTTP with failed login"),
    ([2121, 0, 1, 5], "FTP brute force"),
    ([9999, 0, 0, 1], "Unknown port scan"),
    ([2222, 1, 0, 3], "SSH port scan"),
]

for features, description in attack_tests:
    features_scaled = scaler.transform([features])
    prediction = model.predict(features_scaled)[0]
    score = model.decision_function(features_scaled)[0]
    status = "🚨 ANOMALY" if prediction == -1 else "❌ MISSED"
    print(f"  {description:30s} Pred: {prediction:+2d} | Score: {score:+.4f} → {status}")

print("\n" + "="*70)
print("MODEL DETAILS:")
print(f"  Algorithm: One-Class SVM (better for anomaly detection)")
print(f"  Features: [port, is_ssh, failed_login, num_attempts]")
print(f"  Training samples: {len(X_train)} normal patterns")
print(f"  Expected outlier rate: 5%")
print("="*70)
print("\nKEY BEHAVIORS:")
print("  ✅ Ports 8080, 2121, 2525 with no failures = NORMAL")
print("  🚨 Port 2222 (SSH honeypot) = ANOMALY")
print("  🚨 Any failed login = ANOMALY")
print("  🚨 Unknown ports = ANOMALY")
print("  🚨 Multiple attempts = ANOMALY")
print("="*70)