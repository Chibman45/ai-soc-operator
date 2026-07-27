# AI SOC Operator - Issues Analysis

## Critical Issues Found

### 1. ❌ Alert Ingestion (Partial - Missing Webhooks)

**File:** `web/app.py` (line 366-391), `scripts/orchestrator.py`

**Problem:**
- ✅ CLI ingestion works (`--alert` flag)
- ✅ File upload works
- ❌ **NO webhook endpoint** for real-time alert ingestion from Wazuh/SIEM
- ❌ **NO alert polling mechanism** from Wazuh Manager
- ❌ **NO automatic playbook routing** through web portal

**What's missing:**
```
Missing endpoints:
- POST /api/webhooks/wazuh  (receive alerts from Wazuh webhook)
- POST /api/webhooks/generic (generic alert ingestion)
- GET  /api/alerts/pending   (poll for new alerts)
```

**Impact:** Users can only manually upload alerts via CLI or web form. No real-time SOC integration.

---

### 2. ❌ Wazuh Integration (API Configuration Incomplete)

**File:** `scripts/soc_client/wazuh.py` (lines 77-155)

**Problems:**

#### a) Missing Wazuh Manager Alert Search
- ✅ `get_manager_info()` works
- ✅ `get_rules()` works  
- ❌ **Manager API has NO direct alert search** - the code calls `/alerts/agents/{agent_id}` which may not exist in all Wazuh versions
- ❌ **No fallback to Indexer** if Manager API fails

#### b) Wazuh Indexer Configuration Missing
- The code expects `wazuh_indexer` platform config (line 91-98 in orchestrator.py)
- **Missing environment variable setup:** needs `WAZUH_INDEXER_USERNAME` and `WAZUH_INDEXER_PASSWORD`
- **No documentation** on how to configure Wazuh Indexer in web portal settings

#### c) No Active Alert Monitoring
- Code can only PULL alerts on-demand
- **Cannot RECEIVE alerts from Wazuh webhook**

**What's needed:**
```python
# Missing in wazuh.py:
def get_alerts_summary(self) -> dict[str, Any]:
    """Get alert statistics"""
    return self.get("/alerts/summary")  # Doesn't exist

def get_agent_by_name(self, agent_name: str) -> dict[str, Any]:
    """Lookup agent ID by name before searching alerts"""
```

**Impact:** Can't reliably search Wazuh alerts. Indexer setup is undocumented.

---

### 3. ⚠️ TheHive Integration (API Endpoints Incomplete)

**File:** `scripts/soc_client/thehive.py`

**Problems:**

#### a) Missing Response Action Endpoints
```python
# Missing methods:
def assign_case(self, case_id: str, assignee: str) -> dict[str, Any]:
    # Line 59: update_case() exists but no direct assignment
    
def mark_case_as_resolved(self, case_id: str) -> dict[str, Any]:
    # No way to close/resolve cases properly
    
def export_case(self, case_id: str, format: str = "pdf") -> bytes:
    # No export functionality
```

#### b) Alert Handling is Incomplete
- Line 169-183: `handle_alert()` only handles "import to case"
- **Missing:** Update alert status, mark as resolved, delete alerts

#### c) No Observable Search
```python
# Missing:
def search_observables(self, case_id: str, query: str) -> list[dict]:
    # Can't find observables by type or value
```

#### d) No Task Progress Tracking
- Can create tasks but no `list_tasks()` method
- Can't track task completion percentage per case

**Impact:** Limited case management capability. Can't fully sync case status back to alerts.

---

### 4. ⚠️ MISP Sync (Backend Exists, Frontend Broken)

**File:** `scripts/soc_client/enrichment.py` (assumed), no direct MISP client found

**Problems:**

#### a) No MISP Client Module
- Orchestrator tries to use enrichment client (line 31-32)
- **No `scripts/soc_client/misp.py` exists**
- EnrichmentClient may stub it but no real implementation

#### b) Missing Web Portal Frontend
- Settings page doesn't show MISP configuration form
- Can't enter `MISP_API_KEY` or MISP base URL through web UI
- Only supports via environment variables (line 157 in web/app.py: `"MISP_API_KEY"`)

#### c) No Sync Mechanism
- Can't push indicators TO MISP
- Can only query MISP for enrichment
- No sync schedule or background job

**Impact:** MISP integration is one-way read-only. Can't contribute threat intel back.

---

### 5. ❌ Run Agent Process Issues

**File:** `web/app.py` (line 366-465)

**Problems:**

#### a) Background Thread Issues
```python
# Line 386-388: Thread spawning without tracking
thread = threading.Thread(
    target=_execute_run, args=(run_id, playbook, alert_file), daemon=True
)
thread.start()  # ❌ Daemon thread = killed when Flask exits!
```

**Issue:** If Flask server restarts, all running playbooks are killed mid-execution.

#### b) No Run Resumption
- If a thread crashes, there's no way to resume
- Status is updated in DB but thread lifecycle is not tracked

#### c) Missing Run Status Tracking
```python
# API exists (line 516-531) but:
# - No /api/run/status return for incomplete runs
# - No way to PAUSE/RESUME a run
# - No way to CANCEL a run
```

#### d) No Timeout Enforcement
```python
# Line 420-426: subprocess timeout is 300s
# But if subprocess hangs inside a tool call:
# - No intermediate checkpoints
# - Thread waits forever (daemon kills it, loses data)
```

#### e) Parallel Run Conflict
- No locking mechanism if same playbook runs twice
- Could cause race conditions in report/case writing

**Impact:** Long-running playbooks can be lost. Can't monitor/control them.

---

## Summary Table

| Component | Status | Issue | Severity |
|-----------|--------|-------|----------|
| **File Upload** | ✅ FIXED | Database constraint fixed | - |
| **Alert Ingestion** | ⚠️ Partial | No webhooks, manual only | HIGH |
| **Wazuh Manager** | ⚠️ Partial | Alert search unreliable | HIGH |
| **Wazuh Indexer** | ❌ Missing | Config/setup undocumented | HIGH |
| **TheHive** | ⚠️ Partial | Missing case resolution, exports | MEDIUM |
| **MISP** | ❌ Missing | No sync capability | MEDIUM |
| **Agent Execution** | ❌ Broken | Daemon threads, no resumption | CRITICAL |
| **Web Portal** | ⚠️ Partial | Missing Wazuh Indexer config UI | MEDIUM |

---

## Recommended Fixes (Priority Order)

### CRITICAL (Do First)
1. **Fix daemon thread execution** - Use ThreadPoolExecutor with proper lifecycle management
2. **Implement run cancellation** - Add `/api/runs/<id>/cancel` endpoint
3. **Add webhook receiver** - Implement `/api/webhooks/wazuh` for real-time alerts

### HIGH
4. **Complete Wazuh Indexer** - Add proper ES query construction + web UI form
5. **Document Wazuh setup** - Add setup guide in docs/
6. **Fix TheHive case closure** - Add `mark_resolved()` method

### MEDIUM
7. **Implement MISP client** - Create `scripts/soc_client/misp.py`
8. **Add task progress** - Implement task listing for cases
9. **Fix web portal config** - Add missing platform config forms
