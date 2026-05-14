# PALADIN – HDL, LLD, Working (Diagrams) and Step-by-Step Run Guide

This document uses **ASCII/text diagrams** only (no Mermaid). You can copy the diagrams and sections into the README or keep them here.

---

## 1. High-Level Design (HDL)

PALADIN has four layers: Deception, Transport, Intelligence, and Presentation. Data moves one way from traps to the war room.

**HDL – Block diagram (four layers):**

```
    +------------------+     +------------------+     +------------------+     +------------------+
    |  1. DECEPTION    |     |  2. TRANSPORT    |     |  3. INTELLIGENCE |     |  4. PRESENTATION  |
    |                  |     |                  |     |                  |     |                  |
    |  HTTP   FTP  SMTP|     |  Filebeat        |     |  Consumer (LSTM)  |     |  Streamlit        |
    |  Honeypots       |---->|  Redis           |---->|  Risk + MITRE     |---->|  Dashboard        |
    |  Cowrie (SSH)    |     |  (message queue) |     |  Enriched alerts  |     |  Elasticsearch    |
    |                  |     |                  |     |                  |     |                  |
    +------------------+     +------------------+     +------------------+     +------------------+
          TRAP                    PIPELINE                 BRAIN                    WAR ROOM
```

**HDL – Sequence (who talks to whom):**

```
  Attacker      Honeypots      Filebeat      Redis       Consumer       ES         Dashboard
      |              |              |           |              |          |              |
      |-- request -->|              |           |              |          |              |
      |              |-- log file -->|           |              |          |              |
      |              |              |-- push -->|              |          |              |
      |              |              |           |-- subscribe ->|          |              |
      |              |              |           |-- message --->|          |              |
      |              |              |           |              |-- LSTM   |              |
      |              |              |           |              |-- index->|              |
      |              |              |           |              |          |<-- query -----|
      |              |              |           |              |          |              |
```

---

## 2. Low-Level Design (LLD)

**LLD – Data flow diagram (where data lives and moves):**

```
  EXTERNAL ENTITIES
  =================
       [Attacker]                    [Analyst]
            |                             ^
            v                             |
  +-------------------+                   |
  |  Honeypots        |                   |
  |  HTTP:8080        |                   |
  |  FTP:2121         |  log lines        |
  |  SMTP:2525        |  (JSON)            |
  |  Cowrie SSH:2222  |                    |
  +--------+----------+                    |
           |                               |
           v                               |
  +-------------------+                   |
  |  Shared Volume    |                   |
  |  /shared_logs/    |                   |
  |  *.log, *.json    |                   |
  +--------+----------+                    |
           |                               |
           v                               |
  +-------------------+                   |
  |  Filebeat         |  Redis key         |
  |  (log shipper)    |  honeypot_logs     |
  +--------+----------+                    |
           |                               |
           v                               |
  +-------------------+                   |
  |  Redis            |  pub/sub or list   |
  |  channel/key:     |  honeypot_logs     |
  +--------+----------+                    |
           |                               |
           v                               |
  +-------------------+                   |
  |  Consumer (LSTM)  |  enriched doc      |
  |  82-dim features  |  (ai_prediction,   |
  |  paladin_lstm.h5  |   mitre, status)   |
  +--------+----------+                    |
           |                               |
           v                               |
  +-------------------+                   |
  |  Elasticsearch   |  index:            |
  |  honeypot-logs    |  query for UI      |
  +--------+----------+                    |
           |                               |
           v                               |
  +-------------------+                   |
  |  Dashboard       |  KPIs, charts,     |
  |  Streamlit:8501   |  live log table   |
  +-------------------+-------------------+
```

**LLD – Component summary:**

| Component        | Role                          | Input                    | Output                         |
|-----------------|-------------------------------|--------------------------|--------------------------------|
| Honeypots       | Trap traffic, write logs      | Network requests         | JSON log lines on shared vol   |
| Filebeat        | Tail logs, send to Redis     | Log files                | Messages to Redis key           |
| Redis           | Queue/channel                | Log messages             | Same messages to consumer       |
| Consumer (LSTM) | Classify, enrich, store      | Log JSON + network_features | Enriched doc to ES           |
| Elasticsearch   | Store and query              | Enriched documents       | Search/aggregation results      |
| Dashboard       | Visualize                    | ES query results         | Charts, table, KPIs            |

---

## 3. Working of the Project (End-to-End Flow)

**Step-by-step flow (what happens in order):**

```
  STEP 1: Attacker hits a honeypot (e.g. HTTP:8080 or SSH:2222).
          |
  STEP 2: Honeypot writes one log line (JSON) to shared volume
          (e.g. /shared_logs/http_honeypot.json or cowrie.json).
          |
  STEP 3: Filebeat tails those files and pushes each line to Redis
          (key/channel: honeypot_logs).
          |
  STEP 4: Consumer is subscribed to honeypot_logs. It receives the
          message. For LSTM path it needs an 82-dim network_features
          array (from trigger script or future log parsing).
          |
  STEP 5: Consumer scales features, runs LSTM (paladin_lstm.h5),
          gets class (e.g. DDoS, Benign). It computes risk score
          and MITRE tactics, sets ai_final_status (BLOCKED/etc).
          |
  STEP 6: Consumer indexes the enriched document into Elasticsearch
          index "honeypot-logs".
          |
  STEP 7: Dashboard (Streamlit) queries ES every N seconds, runs
          aggregations (timeline, attack types, top IPs), and
          displays KPIs, charts, and live log table.
          |
  STEP 8: Analyst sees the event on the dashboard and can react
          (or later use GenAI "Explain" for a summary).
```

**Working – Sequence view (simplified):**

```
  Attacker --> Honeypot --> [Log file] --> Filebeat --> Redis --> Consumer --> ES --> Dashboard --> Analyst
                (trap)      (volume)      (ship)      (queue)    (LSTM+MITRE) (store) (visualize)
```

---

## 4. How to Run the Project (Step-by-Step in Detail)

### Step 1: Prerequisites

- Install **Docker** and **Docker Compose** on your machine.
- On **Linux or WSL**, set virtual memory for Elasticsearch (run once):
  - `sudo sysctl -w vm.max_map_count=262144`
  - On WSL with Docker Desktop: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`
- Optional: **Python 3** and **pip** on the host if you want to run `trigger_critical.py` from the host (and have `redis`, `numpy` installed).

### Step 2: Clone and go to project root

```bash
git clone <your-repo-url>
cd PALADIN---Protective-Advanced-Learning-AI-Defense-Intelligence-Network
```

Use the branch you need (e.g. `fixing-broken-pipeline`):

```bash
git checkout fixing-broken-pipeline
```

### Step 3: Start all services

From the project root (where `docker-compose.yml` is):

```bash
docker-compose up -d --build
```

- First time: building images can take several minutes.
- Wait about **60 seconds** after all containers are up so Elasticsearch and the consumer can start.

### Step 4: Check that containers are running

```bash
docker-compose ps
```

You should see running containers for: http-honeypot, ftp-honeypot, smtp-honeypot, cowrie, redis, filebeat, consumer (honeypot-consumer), elasticsearch, kibana (optional), dashboard (paladin-dashboard).

### Step 5: Open the dashboard

In a browser go to:

**http://localhost:8501**

You should see the PALADIN dashboard (KPIs, charts, live log table). If there is no data yet, the tables/charts may be empty.

### Step 6: Generate a test attack (so the LSTM and dashboard get data)

The consumer on branch `fixing-broken-pipeline` listens on Redis **channel** `honeypot_logs` and expects a JSON body with an 82-dimensional `network_features` array. The script `trigger_critical.py` does that.

From the **host** (with Redis port 6379 mapped to localhost):

```bash
# Install dependencies if you run from host
pip install redis numpy

# Run from project root
python trigger_critical.py
```

You should see a message like: attack fired, check consumer logs and dashboard.

### Step 7: Confirm the event on the dashboard

- Refresh or wait for the dashboard’s next refresh (it polls ES).
- You should see a new row in the live log table and updated KPIs (e.g. Total Events, Peak Risk).

### Step 8: Optional – view logs

- **Consumer logs:** `docker-compose logs -f honeypot-consumer`
- **Dashboard logs:** `docker-compose logs -f paladin-dashboard`
- **Elasticsearch:** http://localhost:9200 (e.g. `curl http://localhost:9200/honeypot-logs/_search?pretty`)

### Step 9: Stop the project

```bash
docker-compose down
```

To remove volumes as well (clears ES and log data):

```bash
docker-compose down -v
```

---

## 5. Quick reference

| What              | Where / Command                          |
|-------------------|------------------------------------------|
| Dashboard         | http://localhost:8501                    |
| Kibana            | http://localhost:5601                    |
| Elasticsearch     | http://localhost:9200                    |
| Trigger test hit  | `python trigger_critical.py` (from host) |
| Consumer service  | `honeypot-consumer` (in docker-compose)  |
| ES index          | `honeypot-logs`                          |
| Redis channel/key | `honeypot_logs`                          |

---

You can copy the diagrams and sections above into the main README or link to this file from the README.
