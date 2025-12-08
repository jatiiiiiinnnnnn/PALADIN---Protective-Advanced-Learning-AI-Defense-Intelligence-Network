# 🛡️ PALADIN: Protective Advanced Learning AI Defense Intelligence Network

**A Next-Generation Hybrid Intrusion Detection System (IDS) with Real-Time Threat Intelligence**

![Status](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.9-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📖 Table of Contents
- [Abstract](#-abstract)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Technology Stack](#-technology-stack)
- [Installation & Setup](#-installation--setup)
- [Usage Guide](#-usage-guide)
- [The AI Engine](#-the-ai-engine)
- [Dashboard](#-dashboard)
- [Project Structure](#-project-structure)
- [Future Scope](#-future-scope)
- [Contributors](#-contributors)

---

## 📝 Abstract
PALADIN is a cutting-edge Intrusion Detection System designed to overcome the limitations of traditional, stateless security tools. By integrating **Deception Technology (Honeypots)** with a **Hierarchical AI Core**, PALADIN detects both known threats and zero-day anomalies in real-time. It features a novel **Conflict Resolution Engine** to minimize false positives and a **Rule-Based Behavioral Analyzer** to detect multi-stage attack campaigns ("Kill Chains"). All alerts are automatically mapped to the **MITRE ATT&CK** framework for immediate strategic context.

---

## 🚀 Key Features
* **Hybrid Detection:** Combines Supervised Learning (Random Forest + XGBoost) for known threats with Unsupervised Learning (One-Class SVM) for zero-day anomalies.
* **Stateful Memory:** Tracks attacker behavior over time using a sliding window to detect complex, multi-stage campaigns that stateless systems miss.
* **Real-Time Context:** Automatically maps alerts to **MITRE ATT&CK** Tactics and Techniques (e.g., T1110: Brute Force) and calculates a dynamic **Risk Score**.
* **Deception Layer:** Deploys high-interaction (Cowrie) and low-interaction honeypots to generate high-fidelity, self-sourced threat data.
* **Resilient Architecture:** Built on a decoupled Microservices architecture using **Redis** for backpressure management and **Elasticsearch** for scalable storage.

---

## 🏗️ System Architecture
The system follows a four-layer data pipeline:

1.  **Sensor Layer:** Honeypots (Cowrie, HTTP, FTP, SMTP) capture raw attack traffic.
2.  **Transport Layer:** **Filebeat** ships logs to a **Redis** message queue, ensuring zero data loss during high-load attacks.
3.  **Intelligence Layer:** The **Consumer** service processes logs using the AI Ensemble, Behavioral Engine, and MITRE Mapper.
4.  **Presentation Layer:** Processed intelligence is stored in **Elasticsearch** and visualized in a real-time **Streamlit** dashboard.

---

## 🛠️ Technology Stack
* **Core Logic:** Python 3.9
* **Containerization:** Docker, Docker Compose
* **Machine Learning:** Scikit-Learn, XGBoost
* **Data Pipeline:** Redis, Filebeat, Elasticsearch
* **Visualization:** Streamlit, Plotly Express
* **Honeypots:** Cowrie (SSH/Telnet), Custom Python Scripts (HTTP/FTP/SMTP)

---

## ⚙️ Installation & Setup

### Prerequisites
* **Docker Desktop** (running on Windows/Linux/Mac)
* **Git**
* **Python 3.9+** (optional, for local script execution)

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/PALADIN-IDS.git](https://github.com/YOUR_USERNAME/PALADIN-IDS.git)
cd PALADIN-IDS
````

### 2\. Set Up Environment Variables (Optional)

If you want to use the GenAI features, create a `.env` file in the `dashboard` directory or set the variable in `docker-compose.yml`:

```yaml
# In docker-compose.yml -> dashboard service -> environment
- GEMINI_API_KEY=your_api_key_here
```

### 3\. Build and Launch

Run the entire system with a single command:

```bash
docker-compose up -d --build
```

*Wait \~30-60 seconds for Elasticsearch to initialize.*

### 4\. Verify Status

Check if all containers are running:

```bash
docker-compose ps
```

-----

## 🖥️ Usage Guide

### Accessing the Interfaces

  * **🛡️ War Room Dashboard:** [http://localhost:8501](https://www.google.com/search?q=http://localhost:8501)
  * **📊 Kibana (Optional):** [http://localhost:5601](https://www.google.com/search?q=http://localhost:5601)
  * **🗄️ Elasticsearch:** [http://localhost:9200](https://www.google.com/search?q=http://localhost:9200)

### Simulating Attacks

We have provided scripts to test the system's detection capabilities.

  * **Simulate a Critical DoS Attack:**
    ```bash
    python trigger_critical.py
    ```
    *Result:* Watch the dashboard turn red as the Risk Score spikes.
  * **Simulate Normal/Probe Traffic:**
    ```bash
    python trigger_attack.py
    ```

-----

## 🧠 The AI Engine

PALADIN uses a **Hierarchical Ensemble** to make decisions:

1.  **Supervised Layer:** Random Forest (40% weight) + XGBoost (60% weight).
      * *Accuracy:* **99.33%** on CIC-IDS2017.
2.  **Unsupervised Layer:** One-Class SVM (Anomaly Detection).
      * *Role:* Overrides the supervised model if a "Normal" classification has a high anomaly score.
3.  **Conflict Resolution:**
      * `IF (Supervised == Normal) AND (Anomaly == True) -> ALERT: Zero-Day`

-----

## 📂 Project Structure

```text
PALADIN/
├── dashboard/                  # Streamlit Dashboard Code
│   ├── app.py
│   └── requirements.txt
├── log_pipeline/
│   ├── consumer/               # The AI Brain
│   │   ├── consumer.py         # Main Logic
│   │   ├── training/           # ML Models & Logic
│   │   └── models/             # Trained .pkl files
│   └── filebeat/               # Log Shipper Config
├── low_honeypots/              # Custom Trap Scripts
├── high_cowrie/                # SSH Honeypot Config
├── docker-compose.yml          # Orchestration
├── trigger_critical.py         # Attack Simulator
└── README.md                   # You are here
```

-----

## 🔮 Future Scope

  * **Automated Response (SOAR):** Integration with firewalls (`iptables`) to auto-block high-risk IPs.
  * **Adversarial Training:** Hardening models against AI-generated evasion attacks.
  * **Federated Learning:** Enabling privacy-preserving model updates across distributed nodes.

-----

## 👥 Contributors

  * **Jatin Hans** - *Lead Developer & Architect*
  * **Gauri Bhardwaj** - *Research & Documentation*
  * **Manideep Singh** - *Testing & Validation*

-----

**University Project | 2025**

