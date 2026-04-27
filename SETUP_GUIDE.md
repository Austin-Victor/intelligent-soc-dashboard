# SOC IDS — Real Backend Setup Guide
## How to make your project a fully working system

---

## What You Now Have

| File | Purpose |
|------|---------|
| `network_agent.py` | Captures REAL live packets, runs all 15 detection rules, saves alerts to database |
| `database.py` | SQLite database — stores alerts, logs, and stats permanently |
| `log_parser.py` | Parses uploaded log files and flags suspicious lines |
| `requirements.txt` | All Python packages needed |

---

## Step 1 — Install Npcap (One-time, Windows only)

Npcap lets Python capture real network packets on Windows.

1. Go to: https://npcap.com/#download
2. Download and run the installer
3. During install, check **"Install Npcap in WinPcap API-compatible Mode"**
4. Restart your laptop after installation

---

## Step 2 — Install Python packages

Open **Command Prompt** or **PowerShell** in your project folder and run:

```
pip install -r requirements.txt
```

---

## Step 3 — Connect your React dashboard to the real backend

In your React SOC_Dashboard.jsx, find where you connect to the WebSocket.
Replace any fake/local URL with:

```javascript
const socket = io("http://localhost:5000");
```

And to load alert history when the dashboard opens, add this after connecting:

```javascript
socket.on("connect", () => {
  socket.emit("request_history", { limit: 50 });
});

socket.on("alert_history", (data) => {
  setAlerts(data.alerts);  // populate your alerts state
});

socket.on("real_alert", (alert) => {
  setAlerts(prev => [alert, ...prev.slice(0, 49)]);
});
```

To fetch stats from the database for your metrics cards, call the REST API:

```javascript
useEffect(() => {
  fetch("http://localhost:5000/api/stats")
    .then(res => res.json())
    .then(data => setStats(data.stats));
}, []);
```

To send uploaded log files for real parsing, POST the file text:

```javascript
fetch("http://localhost:5000/api/logs/parse", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ text: fileContent, filename: file.name })
})
.then(res => res.json())
.then(data => setLogResults(data));
```

---

## Step 4 — Add the log parse endpoint to network_agent.py

Add this route to your `network_agent.py` Flask app (paste before `if __name__ == "__main__"`):

```python
from log_parser import parse_and_store

@app.route("/api/logs/parse", methods=["POST"])
def api_parse_log():
    data     = request.get_json()
    text     = data.get("text", "")
    filename = data.get("filename", "uploaded")
    result   = parse_and_store(text, filename)
    return jsonify({"status": "ok", **result})

@app.route("/api/logs", methods=["GET"])
def api_get_logs():
    from database import get_log_entries
    flagged_only = request.args.get("flagged", "false").lower() == "true"
    entries = get_log_entries(limit=200, flagged_only=flagged_only)
    return jsonify({"status": "ok", "entries": entries})
```

---

## Step 5 — Run the system

**IMPORTANT: Run as Administrator** (required for packet capture)

Right-click Command Prompt → "Run as Administrator", then:

```
cd path\to\your\project
python network_agent.py
```

You will see:
```
============================================================
  SOC Network-Based IDS Agent — Real Backend
============================================================
[DB] Database initialized: soc_ids.db
  Detections active:
    ✓ Port Scan (RULE-001)
    ✓ SYN Flood (RULE-002)
    ...
[*] Starting packet capture on all interfaces...
[*] WebSocket server running on http://localhost:5000
```

Then start your React dashboard normally:
```
npm run dev
```

---

## Step 6 — How to test that it's working

Open your browser and visit:
- http://localhost:5000/api/health   → should show agent is online
- http://localhost:5000/api/stats    → shows alert counts from database
- http://localhost:5000/api/alerts   → shows all saved alerts

When your laptop is on a network and traffic flows, alerts will appear
automatically in the dashboard within milliseconds.

---

## What the database file looks like

A file called `soc_ids.db` will be created in your project folder automatically.
It stores everything permanently — even after you restart the agent, all previous
alerts are still there. You can open it with DB Browser for SQLite (free app)
to view the raw data: https://sqlitebrowser.org

---

## API Endpoints Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/health | GET | Check if agent is running |
| /api/stats | GET | Total alerts, critical count, by-type breakdown |
| /api/alerts | GET | Fetch alerts (optional: ?limit=50&severity=CRITICAL) |
| /api/alerts/<id> | GET | Single alert detail |
| /api/logs/parse | POST | Parse uploaded log file text |
| /api/logs | GET | Fetch stored log entries |

---

## Troubleshooting

**"No module named scapy"** → Run `pip install scapy` again as Administrator

**"Permission denied" on packet capture** → Make sure you ran Command Prompt as Administrator

**Dashboard shows no alerts** → Check that the agent terminal shows "[*] Starting packet capture..."
and that your React app is connecting to http://localhost:5000

**Npcap not found error** → Reinstall Npcap and restart your laptop
