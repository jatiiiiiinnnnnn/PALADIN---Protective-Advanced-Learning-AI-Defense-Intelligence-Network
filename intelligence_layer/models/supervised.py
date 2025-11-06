# supervised.py
"""
This file defines training functions for supervised models:
- Random Forest
- XGBoost
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb
from data_preprocess import load_cicids_csv  # Your function to load CIC-IDS2017 dataset

def train_supervised_model(sample_frac=0.1):
    """
    Trains both Random Forest and XGBoost classifiers on CIC-IDS2017 dataset.
    
    Parameters:
    - sample_frac: Fraction of dataset to use (for memory safety)
    
    Returns:
    - clf_rf: Trained Random Forest model
    - clf_xgb: Trained XGBoost model
    - encoder: Label encoder used for target labels
    """
    print("\n[1] Loading CIC-IDS2017 dataset...")
    X, y, encoder = load_cicids_csv(sample_frac=sample_frac)  # Returns X (features), y (labels), encoder
    
    # Split into train/test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # ------------------- Random Forest -------------------
    print("\n[2] Training Random Forest classifier...")
    clf_rf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf_rf.fit(X_train, y_train)
    y_pred_rf = clf_rf.predict(X_test)
    
    print("Random Forest Accuracy:", accuracy_score(y_test, y_pred_rf))
    print("Random Forest Classification Report:\n", classification_report(y_test, y_pred_rf))
    
    # ------------------- XGBoost -------------------
    print("\n[3] Training XGBoost classifier...")
    clf_xgb = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42)
    clf_xgb.fit(X_train, y_train)
    y_pred_xgb = clf_xgb.predict(X_test)
    
    print("XGBoost Accuracy:", accuracy_score(y_test, y_pred_xgb))
    print("XGBoost Classification Report:\n", classification_report(y_test, y_pred_xgb))
    
    print("\n✅ Both Random Forest and XGBoost models trained successfully!")
    return clf_rf, clf_xgb, encoder
