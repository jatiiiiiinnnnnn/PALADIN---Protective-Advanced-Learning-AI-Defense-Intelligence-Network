# 🛡️ **P.A.L.A.D.I.N.**

### **Protective Advanced Learning AI Defense Intelligence Network**

> **"Moving from Reactive Defense to Proactive Intelligence."**

---

## 📖 **Table of Contents**

* [🎯 Abstract & Problem Statement](https://www.google.com/search?q=%23-abstract--problem-statement)
* [🚀 Key Features](https://www.google.com/search?q=%23-key-features)
* [🏗️ System Architecture](https://www.google.com/search?q=%23-system-architecture)
* [🧠 The Intelligence Core (Algorithms)](https://www.google.com/search?q=%23-the-intelligence-core-algorithms)
* [🛠️ Technology Stack](https://www.google.com/search?q=%23-technology-stack)
* [📊 Performance & Results](https://www.google.com/search?q=%23-performance--results)
* [⚡ Installation & Deployment](https://www.google.com/search?q=%23-installation--deployment)
* [🖥️ Usage & Dashboard](https://www.google.com/search?q=%23-usage--dashboard)
* [📂 Project Structure](https://www.google.com/search?q=%23-project-structure)
* [🔮 Future Scope](https://www.google.com/search?q=%23-future-scope)
* [👥 Contributors](https://www.google.com/search?q=%23-contributors)

---

## 🎯 **Abstract & Problem Statement**

Traditional Intrusion Detection Systems (IDS) are failing. They suffer from **Stateless Blindness** (missing multi-stage attacks), **Zero-Day Vulnerability** (inability to detect novel threats), and **Contextual Gaps** (flooding analysts with raw, meaningless alerts).

**PALADIN** is a next-generation Hybrid IDS that bridges these gaps. It integrates **Deception Technology** (Honeypots) with a **Hierarchical AI Engine** to generate high-fidelity threat intelligence. By combining supervised learning for known threats, unsupervised learning for zero-day anomalies, and behavioral state analysis for kill-chain detection, PALADIN provides a 360-degree view of the threat landscape.

---

## 🚀 **Key Features**

* **🕵️‍♂️ Hybrid Deception Network:** Deploys high-interaction (Cowrie SSH) and low-interaction (HTTP/FTP/SMTP) honeypots to trap adversaries and generate self-sourced datasets.
* **🧠 Hierarchical AI Ensemble:** Combines **Random Forest** and **XGBoost** for precision, supervised by a **One-Class SVM** for zero-day anomaly detection.
* **🔗 Stateful Behavioral Analysis:** Tracks attacker "Kill Chains" (e.g., Recon  Brute Force  Exploit) using a sliding-window sequence analyzer, catching attacks that stateless models miss.
* **🗺️ Automated MITRE ATT&CK Mapping:** Instantly maps technical alerts to strategic T-Codes (e.g., **T1110: Brute Force**) and calculates a dynamic **Risk Score**.
* **🛡️ Resilient Microservices:** Built on a decoupled Docker architecture with **Redis Backpressure** handling to survive massive DoS floods without data loss.
* **🤖 GenAI Integration:** Integrated LLM engine to auto-generate human-readable incident summaries and remediation steps.

---

## 🏗️ **System Architecture**

PALADIN operates on a four-layer pipeline designed for speed, scalability, and resilience.

| Layer | Component | Function |
| --- | --- | --- |
| **1. Deception** | **Honeypots (Cowrie, Custom)** | The "Trap." Captures raw shell commands, malware, and traffic. Writes logs to a secure volume. |
| **2. Transport** | **Filebeat + Redis** | The "Pipeline." Ships logs in real-time to an in-memory message queue, ensuring high-velocity data ingestion and backpressure handling. |
| **3. Intelligence** | **Consumer Engine** | The "Brain." Runs the AI Ensemble, Anomaly Detector, and Sequence Analyzer to classify threats. |
| **4. Presentation** | **Streamlit + Elasticsearch** | The "War Room." Visualizes live attacks, geo-origins, and system health status. |

---

## 🧠 **The Intelligence Core (Algorithms)**

PALADIN uses a sophisticated "Check-and-Balance" system to classify traffic.

### **1. Supervised Ensemble (The Expert)**
We combine the stability of **Random Forest** ($P_{RF}$) with the precision of **XGBoost** ($P_{XGB}$) using a weighted soft-voting formula:

$$P_{final} = 0.4 \times P_{RF} + 0.6 \times P_{XGB}$$

### **2. Unsupervised Anomaly Detector (The Skeptic)**
To catch Zero-Days, a **One-Class SVM** learns the boundary of "Normal" traffic. It calculates the signed distance ($f(x)$) of a packet from this boundary:

$$f(x) = \text{sgn}\left( \sum_{i=1}^{n} \alpha_i K(x_i, x) - \rho \right)$$

* **Logic:** If the Supervised model says "Normal" but the Unsupervised model flags an "Anomaly" ($f(x) = -1$), the system overrides the decision to **"Unknown Threat"**.

### **3. Behavioral Threat Scoring (The Memory)**
We calculate a dynamic **Threat Velocity Score** using a Sigmoid Decay function to distinguish between fast machine attacks and slow human errors:

$$S_{rate} = \frac{1}{1 + e^{(\Delta t - 15)/10}}$$

* **Result:** Attacks faster than 15s trigger high-risk alerts; human-speed traffic is ignored.

---

## 🛠️ **Technology Stack**

* **Infrastructure:** Docker, Docker Compose, WSL2 (Linux Kernel).
* **Languages:** Python 3.9 (Core Logic), Bash.
* **AI/ML:** Scikit-Learn, XGBoost, TensorFlow, Joblib.
* **Data Pipeline:** Redis (Message Broker), Filebeat (Shipper).
* **Storage:** Elasticsearch (Hot Storage), PostgreSQL (Structured Data).
* **Frontend:** Streamlit (Dashboard), Plotly (Charts).
* **External APIs:** Google Gemini (GenAI), VirusTotal (Threat Intel).

---

## 📊 **Performance & Results**

PALADIN was validated on the **CIC-IDS2017** dataset and a 30-day live deployment.

* **Overall Accuracy:** **99.33%** (vs. 98.8% for standalone Decision Trees).
* **Inference Speed:** **75ms** per event (Real-time production ready).
* **Zero-Day Detection:** Achieved **100% Recall** on rare attacks like `Heartbleed` and `Infiltration` using SMOTE oversampling.
* **Uptime:** 99.7% availability during live stress tests.

---

## ⚡ **Installation & Deployment**

### **Prerequisites**

* Docker Desktop & Docker Compose
* Python 3.9+ (Optional for local scripts)
* **WSL2** (If on Windows)

### **1. Clone Repository**

```bash
git clone https://github.com/yourusername/PALADIN-IDS.git
cd PALADIN-IDS

```

### **2. System Config (Crucial for Elasticsearch)**

If running on Linux/WSL, you must increase the virtual memory map count:

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144

```

### **3. Launch Microservices**

```bash
docker-compose up -d --build

```

*Wait ~60 seconds for the Elasticsearch cluster to form and the AI models to load.*

---

## 🖥️ **Usage & Dashboard**

### **Access the War Room**

Navigate to **[http://localhost:8501](https://www.google.com/search?q=http://localhost:8501)** in your browser.

* **Live Attack Timeline:** Watch attacks happen in real-time.
* **MITRE Matrix:** See the strategic breakdown of active threats.
* **GenAI Reports:** Click "Generate Summary" for an LLM-powered incident report.

### **Simulate Attacks**

We provide Python scripts to test the system's detection capabilities safely.

1. **Trigger a Critical DoS Attack:**
```bash
python trigger_critical.py

```


*Result: Watch the "Risk Gauge" spike to Critical (Red).*
2. **Trigger a Stealth Scan:**
```bash
python trigger_scan.py

```


*Result: Watch the "Active Threats" counter increment.*

---

## 📂 **Project Structure**

```text
PALADIN/
├── dashboard/                  # Streamlit UI Code
│   ├── app.py                  # Main Dashboard Logic
│   └── requirements.txt
├── log_pipeline/               # The AI Core
│   ├── consumer/
│   │   ├── consumer.py         # Main Event Loop
│   │   ├── ensemble_predictor.py # AI Logic (RF + XGB + Conflict Engine)
│   │   ├── lstm_analyzer.py    # Behavioral Sequence Engine
│   │   └── models/             # Trained .pkl Models
│   └── filebeat/               # Log Shipper Config
├── low_honeypots/              # Custom Trap Scripts (HTTP/FTP)
├── high_cowrie/                # Advanced SSH Honeypot
├── docker-compose.yml          # Orchestration Config
└── README.md                   # You are here

```

---

## 🔮 **Future Scope**

* **🛡️ Automated Response (SOAR):** Integration with `iptables` to automatically ban IPs with Risk Score > 4.5.
* **🤝 Federated Learning:** Collaborative model training across multiple organizations without sharing sensitive logs.
* **🧠 Deep Learning:** Migration to CNNs/Transformers for raw packet-level analysis.

---

## 👥 **Contributors**

* **Jatin Hans** - *Lead Architect & AI Engineer*
* **Gauri Bhardwaj** - *Data Pipeline & Visualization*
* **Manideep Singh** - *Honeypot Infrastructure & Testing*

---

*Built with ❤️ for the Future of Cybersecurity.*
