# GenAI Integration – Architecture, Files, Code, and Steps

This document describes how the "Explain with AI" (GENERATE REPORT) feature is added to the PALADIN dashboard using Google Gemini: architecture, which files change, full code, and how to run it.

---

## What We Did (Summary)

1. **dashboard/app.py**
   - **Imports:** Added `json` so we can send a compact alert object to Gemini.
   - **New function `get_gemini_explanation(alert, api_key)`:** Takes the latest alert from ES, builds a small JSON (timestamp, source_ip, service, ai_prediction, mitre risk/tactics, etc.), calls Google Gemini (`gemini-1.5-flash`) with a fixed “cybersecurity expert” prompt, and returns the model’s plain-English text (or an error string).
   - **Sidebar:** New section “GENAI ANALYST” with a **GENERATE REPORT** button. On click we set `st.session_state["genai_requested"] = True` so the main area can react on the next run.
   - **Main area (before the live dashboard):** When `genai_requested` is True we fetch the latest log from ES, call `get_gemini_explanation`, and store the result in `st.session_state["genai_report"]` or `st.session_state["genai_error"]`. Then we show either the “AI Incident Summary” box (with **Clear report**) or an error message (with **Clear error**).
   - **Refresh loop refactor:** Replaced the infinite `while True:` loop with a single render pass and, at the end, `time.sleep(refresh_rate)` then `st.rerun()`. That way the script finishes each run and Streamlit can handle the button click; the page still auto-refreshes every N seconds.

2. **dashboard/requirements.txt**
   - Added `google-generativeai` so the dashboard can call the Gemini API.

3. **docker-compose.yml**
   - For the `dashboard` service, added `env_file: .env` so the container gets `GEMINI_API_KEY` from a `.env` file in the project root.

4. **You**
   - Create a `.env` file in the project root with `GEMINI_API_KEY=your_key` (get the key from Google AI Studio). Do not commit `.env` (it is already in `.gitignore`).

---

## 1. Architecture

**Where GenAI sits in the system**

```
  [Dashboard Streamlit App]
           |
           |  User clicks "GENERATE REPORT"
           v
  Fetch latest alert from Elasticsearch (index: honeypot-logs)
           |
           v
  Build compact JSON (timestamp, source_ip, service, ai_prediction, mitre, etc.)
           |
           v
  Call Google Gemini API (gemini-1.5-flash) with prompt:
  "You are a cybersecurity expert. Explain this attack log..."
           |
           v
  Store result in st.session_state["genai_report"]
           |
           v
  Render "AI Incident Summary" box above the main dashboard
```

**Data flow**

- **Input:** One document from ES (the most recent alert in `honeypot-logs`).
- **Output:** Plain-English summary (what happened, severity, 1–3 remediation steps), shown in the dashboard.
- **Config:** `GEMINI_API_KEY` from environment (e.g. `.env`), read by the dashboard container.

**No change to:** Honeypots, Filebeat, Redis, Consumer, or Elasticsearch. Only the dashboard app and its deployment config change.

---

## 2. Files to Update or Add

| File | Action |
|------|--------|
| `dashboard/app.py` | **Edit.** Add GenAI helper, sidebar button, report box, and refactor the refresh loop so the button can be used. |
| `dashboard/requirements.txt` | **Edit.** Add `google-generativeai`. |
| `docker-compose.yml` | **Edit.** Pass `GEMINI_API_KEY` into the dashboard (e.g. `env_file: .env`). |
| `.env` (project root) | **Create (you).** Add `GEMINI_API_KEY=your_key`. Do not commit. |
| `docs/GENAI_INTEGRATION.md` | **Reference.** This file. |

---

## 3. Code and Explanation

### 3.1 `dashboard/requirements.txt`

**Add one line:**

```
google-generativeai
```

**Why:** Official SDK to call the Gemini API from Python.

---

### 3.2 `docker-compose.yml` (dashboard service)

**Add `env_file` so the container gets `GEMINI_API_KEY` from `.env`:**

```yaml
  dashboard:
      build:
        context: ./dashboard
        dockerfile: Dockerfile
      container_name: paladin-dashboard
      ports:
        - "8501:8501"
      env_file: .env
      environment:
        - ELASTICSEARCH_HOST=http://elasticsearch:9200
      depends_on:
        - elasticsearch
      volumes:
        - ./dashboard:/app
      command: streamlit run app.py
```

**Change:** Add `env_file: .env` (and keep or add `environment` as needed). Create `.env` in the project root with `GEMINI_API_KEY=...`.

---

### 3.3 `dashboard/app.py` – Summary of edits

1. **Imports:** Add `json` and `google.generativeai` (with safe import if key is missing).
2. **Function `get_gemini_explanation(alert, api_key)`:** Builds a short JSON of the alert, calls Gemini with the cybersecurity prompt, returns the model text or an error string.
3. **Refactor refresh:** Replace the `while True:` loop with a single render pass; at the end call `time.sleep(refresh_rate)` then `st.rerun()`. This lets the "GENERATE REPORT" button be processed on the next run.
4. **Sidebar:** New section "GENAI ANALYST" above "SYSTEM STATUS" with a "GENERATE REPORT" button. On click, set `st.session_state["genai_requested"] = True`.
5. **Main area (before the live dashboard):** If `genai_requested`, fetch latest log, call `get_gemini_explanation`, store result in `st.session_state["genai_report"]` or `st.session_state["genai_error"]`, clear `genai_requested`. Then, if `genai_report` exists, show the "AI Incident Summary" box and a "Clear report" button.

The sections below give the exact code blocks to add or replace.

---

### 3.4 `dashboard/app.py` – Imports (add at top)

```python
import json
# ... existing imports ...
```

And later (inside the script, before using Gemini), we use a conditional import so the app runs even if the key is missing:

```python
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
```

---

### 3.5 `dashboard/app.py` – Function `get_gemini_explanation`

Add this after the data fetchers (`fetch_recent_logs`, etc.) and before the sidebar:

```python
def get_gemini_explanation(alert, api_key, timeout_sec=10):
    """Call Google Gemini to explain the attack log in plain English."""
    if not api_key or not api_key.strip():
        return "Error: GEMINI_API_KEY is not set. Add it to your .env file."
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key.strip())
        model = genai.GenerativeModel("gemini-1.5-flash")
        # Build compact payload (no huge raw payloads)
        compact = {
            "timestamp": alert.get("timestamp"),
            "source_ip": alert.get("source_ip"),
            "service": alert.get("service"),
            "ai_prediction": alert.get("ai_prediction"),
            "ai_final_status": alert.get("ai_final_status"),
            "event_type": alert.get("event_type"),
        }
        mitre = alert.get("mitre") or {}
        if isinstance(mitre, dict):
            compact["risk_score"] = mitre.get("risk_score")
            compact["tactics"] = mitre.get("tactics")
        prompt = """You are a cybersecurity expert. Below is a single attack log from an intrusion detection system (PALADIN). Explain this log in simple terms for a security analyst.

Include:
1. What happened (one sentence).
2. Severity and risk in plain language.
3. One to three short remediation steps.

Keep the total response under 200 words. Use clear, professional English.

Attack log (JSON):
""" + json.dumps(compact, indent=2)
        response = model.generate_content(prompt, request_options={"timeout": timeout_sec})
        if response and response.text:
            return response.text.strip()
        return "Error: Empty response from Gemini."
    except Exception as e:
        return f"Error: {str(e)}"
```

**Explanation:** We send only a small JSON (no large raw payloads) and a fixed prompt. The model returns plain-English text, which we show in the report box. Errors are returned as strings so the UI can show them.

---

### 3.6 `dashboard/app.py` – Sidebar: add GenAI section

Insert this **before** the "SYSTEM STATUS" section (before `st.markdown("### 📡 SYSTEM STATUS")`):

```python
    st.markdown("---")
    st.markdown("### 🤖 GENAI ANALYST")
    if st.button("GENERATE REPORT", use_container_width=True):
        st.session_state["genai_requested"] = True
    st.markdown("---")
```

**Explanation:** Clicking the button sets a flag. In the main body we check this flag, run the Gemini call once, and store the result so the report appears above the dashboard.

---

### 3.7 `dashboard/app.py` – Main area: handle request and show report

Insert this **after** the main title and subtitle and **before** `live_container = st.empty()`:

```python
# --- GenAI: handle GENERATE REPORT request and show report ---
if st.session_state.get("genai_requested"):
    with st.spinner("Generating AI report..."):
        logs = fetch_recent_logs(1)
        if not logs:
            st.session_state["genai_error"] = "No alerts yet. Trigger an attack or wait for traffic."
            st.session_state["genai_report"] = None
        else:
            api_key = os.getenv("GEMINI_API_KEY", "").strip()
            if not api_key:
                st.session_state["genai_error"] = "GEMINI_API_KEY not set. Add it to .env in the project root."
                st.session_state["genai_report"] = None
            else:
                report = get_gemini_explanation(logs[0], api_key)
                if report.startswith("Error:"):
                    st.session_state["genai_error"] = report
                    st.session_state["genai_report"] = None
                else:
                    st.session_state["genai_report"] = report
                    st.session_state["genai_error"] = None
        st.session_state["genai_requested"] = False

if st.session_state.get("genai_report"):
    st.markdown("### 📋 AI Incident Summary")
    st.markdown('<div class="info-panel">', unsafe_allow_html=True)
    st.markdown(st.session_state["genai_report"])
    st.markdown("</div>", unsafe_allow_html=True)
    if st.button("Clear report"):
        st.session_state.pop("genai_report", None)
        st.session_state.pop("genai_error", None)
        st.rerun()
    st.markdown("<hr>", unsafe_allow_html=True)
elif st.session_state.get("genai_error"):
    st.markdown("### 📋 GenAI Report")
    st.error(st.session_state["genai_error"])
    if st.button("Clear error"):
        st.session_state.pop("genai_report", None)
        st.session_state.pop("genai_error", None)
        st.rerun()
    st.markdown("<hr>", unsafe_allow_html=True)
```

**Explanation:** When the user has clicked "GENERATE REPORT", we fetch the latest alert, call Gemini, and store either the report or an error. We then show the report in the existing `info-panel` style or show the error. "Clear" buttons remove the message and rerun so the UI updates.

---

### 3.8 `dashboard/app.py` – Refactor the refresh loop

**Replace** the block that starts with `while True:` and ends with `time.sleep(refresh_rate)` **with** the same content but **without** the `while True:` wrapper, and **add** `st.rerun()` after the sleep:

- Change:
  ```python
  while True:
      with live_container.container():
          # ... entire dashboard content ...
      time.sleep(refresh_rate)
  ```
- To:
  ```python
  with live_container.container():
      # ... entire dashboard content (unchanged) ...
  time.sleep(refresh_rate)
  st.rerun()
  ```

**Explanation:** With the infinite loop, Streamlit never finished a run, so the sidebar button never "fired". One pass plus `st.rerun()` keeps the page refreshing while allowing the button to be handled on the next run.

---

## 4. Integration Steps (How to Run)

1. **Get a Gemini API key**  
   From [Google AI Studio](https://aistudio.google.com/app/apikey) (or Google Cloud Console), create an API key.

2. **Create `.env` in the project root** (same folder as `docker-compose.yml`):
   ```
   GEMINI_API_KEY=your_key_here
   ```
   Add `.env` to `.gitignore` so the key is not committed.

3. **Apply code changes:**
   - Add `google-generativeai` to `dashboard/requirements.txt`.
   - Add `env_file: .env` to the `dashboard` service in `docker-compose.yml`.
   - Update `dashboard/app.py` as in sections 3.4–3.8 (imports, `get_gemini_explanation`, sidebar button, report handling, loop refactor).

4. **Rebuild and start:**
   ```bash
   docker-compose up -d --build
   ```
   Open http://localhost:8501.

5. **Test:** Trigger an attack (e.g. `python trigger_critical.py`), wait for the event to appear on the dashboard, then click "GENERATE REPORT". An "AI Incident Summary" should appear above the dashboard; if something fails, an error message appears instead.

---

## 5. Quick Reference

| Item | Value |
|------|--------|
| Env var | `GEMINI_API_KEY` |
| Model | `gemini-1.5-flash` |
| Data source | Latest document from ES index `honeypot-logs` |
| Session keys | `genai_report`, `genai_error`, `genai_requested` |
| Button | Sidebar: "GENERATE REPORT" |
