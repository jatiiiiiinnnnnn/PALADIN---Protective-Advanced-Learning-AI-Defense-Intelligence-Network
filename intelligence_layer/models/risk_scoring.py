def compute_risk_score(features: dict) -> float:
    """
    Compute a simple risk score based on given features.
    Example features: {"failed_logins": 3, "suspicious_ip": True}
    """
    score = 0
    score += features.get("failed_logins", 0) * 0.3
    score += 1.0 if features.get("suspicious_ip", False) else 0.0
    score += features.get("anomaly_score", 0.0) * 0.5
    return score
