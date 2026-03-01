# Week 3: GenAI Analyst — Detailed Plan

**Goal:** Add the "Explain with AI" (GENERATE REPORT) button to the Dashboard using Google Gemini.

**Success criteria:** Click button → readable English explanation of the attack log within ~3 seconds.

---

## What I Need From You

| Item | Required? | Notes |
|------|-----------|--------|
| **Google Gemini API Key** | ✅ Yes | You create it; we only use it in `.env` and never commit it. |
| **Nothing else** | — | Rest can be implemented without you (prompt, UI, Docker env pass-through). |

### How You Get the API Key (Monday Feb 16)

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey) (or [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Enable "Generative Language API" → Create credentials → API key).
2. Create an API key.
3. Put it in a file `.env` in the **project root** (same folder as `docker-compose.yml`):
   ```bash
   GEMINI_API_KEY=your_key_here
   ```
4. Ensure `.env` is in `.gitignore` so the key is never committed.

That’s all you need to provide. The rest is implementation below.

---

## 1. Refactor: Make the Button Clickable

**Problem:** The dashboard uses an infinite `while True` loop. The script never finishes a run, so Streamlit never processes sidebar button clicks.

**Solution:** Run **one** dashboard cycle per run, then sleep and trigger a rerun. That way the page keeps auto-refreshing and button clicks are processed on the next run.

**Change in `dashboard/app.py`:**

- Replace:
  ```python
  while True:
      with live_container.container():
          # ... all current content ...
      time.sleep(refresh_rate)
  ```
- With:
  ```python
  with live_container.container():
      # ... exact same content ...
  time.sleep(refresh_rate)
  st.rerun()
  ```

**Result:** Every `refresh_rate` seconds the page reruns and the sidebar (including "GENERATE REPORT") is interactive.

---

## 2. API Setup (Monday)

### 2.1 Environment variable

- **Name:** `GEMINI_API_KEY`
- **Where:** `.env` in project root (and optionally in Docker Compose so the dashboard container sees it).

### 2.2 Docker Compose

- In `docker-compose.yml`, under the `dashboard` service, add:
  ```yaml
  env_file: .env
  # or explicitly:
  environment:
    - ELASTICSEARCH_HOST=http://elasticsearch:9200
    - GEMINI_API_KEY=${GEMINI_API_KEY}
  ```
- Use `env_file: .env` so that any variable in `.env` (including `GEMINI_API_KEY`) is passed into the container.

### 2.3 Dashboard dependency

- Add to `dashboard/requirements.txt`:
  ```text
  google-generativeai
  ```
- Rebuild the dashboard image after adding it.

---

## 3. Dashboard UI (Wednesday)

### 3.1 Where to put the button

- **Place:** Sidebar, in a new section **above** "SYSTEM STATUS", e.g. **"🤖 GENAI ANALYST"**.
- **Label:** `GENERATE REPORT` (or "Explain with AI" as per your roadmap).
- **Behavior:** One clear primary button. When clicked, we generate a report for the **latest alert** (or a selected alert — see below).

### 3.2 Which alert to send to Gemini

**Option A (simplest, recommended for Week 3):** Use the **most recent** alert from `paladin-alerts` (same as the live log feed). One document, full JSON.

**Option B (later):** Let the user select a row in the "LIVE INTERCEPT LOG" table and pass that row’s data to Gemini. (Requires selectable rows or a "Select latest" vs "Select from table" toggle.)

**Plan:** Implement Option A first. We already have `fetch_recent_logs(25)`. Use the first item (latest) as the payload. If there are no logs, show a message: "No alerts yet. Trigger an attack or wait for traffic."

### 3.3 Where to show the explanation

- **Place:** Main area, **above** the "THREAT INTELLIGENCE OVERVIEW" section when the report exists.
- **Container:** A dedicated box (e.g. `st.container()` or a styled `st.markdown` div with class `info-panel` or a new `genai-report-box`).
- **Content:** Title "📋 AI Incident Summary", then the model’s plain-English text. Optionally show "Source alert (summary)" (e.g. timestamp, IP, attack type) above the explanation.
- **Persistence:** Use `st.session_state` to store the last generated report (and optionally the alert it was based on) so that after a rerun the report doesn’t disappear until the user generates a new one or clears it.

---

## 4. Prompt Engineering (Friday)

### 4.1 Role and task

- **Role:** "You are a cybersecurity expert."
- **Task:** "Explain this attack log in simple terms for a security analyst. Include: what happened, severity, and recommended remediation steps. Keep the answer under 200 words and in plain English."

### 4.2 Payload to send

- Send a **compact JSON** of the chosen alert (e.g. the latest from ES). Include at least:
  - `@timestamp`, `src_ip` or `source_ip`, `service`, `ai_attack_type` or `ai_prediction`, `ai_final_status`, `ai_confidence`
  - `mitre` (risk_score, tactics, techniques) if present
  - Optional: `raw_data` / `details` / `event_type` for richer context
- Sanitize: remove any field that might contain huge binary or token-heavy content so we don’t blow the context window.

### 4.3 Prompt template (exact text you can use)

```text
You are a cybersecurity expert. Below is a single attack log from an intrusion detection system (PALADIN). Explain this log in simple terms for a security analyst.

Include:
1. What happened (one sentence).
2. Severity and risk in plain language.
3. One to three short remediation steps.

Keep the total response under 200 words. Use clear, professional English.

Attack log (JSON):
{alert_json}
```

- Replace `{alert_json}` with the compact JSON string (e.g. `json.dumps(alert, indent=2)` or a flattened one-line version).

### 4.4 Model and safety

- **Model:** `gemini-1.5-flash` (fast, good for &lt;3 s response) or `gemini-1.5-pro` if you want slightly better quality and can accept ~3–5 s.
- **Safety:** Use default Gemini safety settings; no need to relax them for this use case.
- **Timeout:** Set a 5–10 s timeout on the client so the UI doesn’t hang; if it times out, show "Report generation timed out. Try again."

---

## 5. Implementation Checklist (Code-Level)

- [ ] **Refactor loop:** Replace `while True` with one pass + `time.sleep(refresh_rate)` + `st.rerun()`.
- [ ] **`.env`:** Create `.env` with `GEMINI_API_KEY=...`; add `.env` to `.gitignore` if not already.
- [ ] **Docker:** Add `env_file: .env` (or pass `GEMINI_API_KEY`) for the `dashboard` service; rebuild.
- [ ] **requirements.txt:** Add `google-generativeai`.
- [ ] **Helper function:** e.g. `get_gemini_explanation(alert: dict, api_key: str) -> str` that:
  - Builds compact alert JSON.
  - Calls Gemini with the prompt above.
  - Returns the model’s text or raises/returns an error message.
- [ ] **Sidebar:** New section "🤖 GENAI ANALYST" with `st.button("GENERATE REPORT")`.
- [ ] **On button click:**  
  - Get latest alert from `fetch_recent_logs(1)` (or first of 25).  
  - If none, show "No alerts yet."  
  - Else call `get_gemini_explanation(alert, os.getenv("GEMINI_API_KEY"))`, store result in `st.session_state["genai_report"]` (and optionally `st.session_state["genai_alert_summary"]`).  
  - If API key missing or call fails, show a clear message ("API key not set" / "Report generation failed").
- [ ] **Main area:** If `st.session_state.get("genai_report")` is set, render the "📋 AI Incident Summary" box above the KPIs; optionally a "Clear report" button that deletes the key from session state.
- [ ] **Styling:** Reuse existing cyberpunk panel styles (e.g. `info-panel` or `alert-box`) so the report box fits the theme.

---

## 6. Weekend Test (Target: &lt;3 s)

- [ ] Click "GENERATE REPORT" with at least one alert in the index → explanation appears.
- [ ] No alerts → friendly message.
- [ ] Invalid or missing API key → clear error, no crash.
- [ ] Response time: aim &lt;3 s with `gemini-1.5-flash`; if &gt;3 s, try smaller payload or faster model.

---

## 7. Optional Later Enhancements

- "Explain with AI" for a **selected** row in the live log table (Option B above).
- Caching the last report per alert id/timestamp so re-clicking doesn’t call the API again.
- Short "Regenerate" and "Copy to clipboard" buttons next to the report.

---

## 8. Summary: What You Do vs What Gets Built

| You | Implementation (code) |
|-----|------------------------|
| Get Gemini API key; add `GEMINI_API_KEY=...` to `.env` | Refactor dashboard loop; add button; Gemini client; prompt; session_state; Docker env_file; requirements |

Once the refactor and env are in place, the rest is a single button, one function call to Gemini, and a box to show the result. I can implement the full flow (refactor + button + Gemini + prompt + Docker/requirements) when you’re ready; you only need to add the API key to `.env`.
