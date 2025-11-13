import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

print("🤖 Training tailored PALADIN model...")

# 1. Define "Normal" Traffic
# We train the model ONLY on your low-interaction ports.
# 8080 (HTTP), 2121 (FTP), 2525 (SMTP) are "normal" for this demo.
X_train = np.array([
    [8080], [8080], [8080], # Web traffic is common
    [2121], [2121],         # FTP is less common
    [2525], [2525]          # SMTP is less common
])

# 2. Train the model
# contamination=0.01 means we truly trust this training data is mostly normal.
model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
model.fit(X_train)

model_filename = '/app/anomaly_detector.pkl'
# ----------------------

# 3. Save the model
joblib.dump(model, model_filename)
print(f"✅ Model saved to: {model_filename}")

# 4. Verify our hypothesis for the demo
print("\n--- PRE-DEMO CHECK ---")
print(f"Port 8080 (HTTP) Score:  {model.decision_function([[8080]])[0]:.4f} (Should be POSITIVE +)")
print(f"Port 2222 (SSH) Score:   {model.decision_function([[2222]])[0]:.4f} (Should be NEGATIVE -)")