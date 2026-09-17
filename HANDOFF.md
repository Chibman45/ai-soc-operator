# Handoff — AI SOC Operator

_Last updated: 2026-09-17_

This document is a self-contained brief for the next agent/developer picking up
this work. It covers **what the overall goal is**, **what has been implemented**,
**what remains**, and the **exact integration points** for the unfinished work.

## Current release status

Phases 0-10 now have a production-oriented single-node baseline on
`codex/phase-0-7-production-hardening`. The release now includes centralized
multi-role authorization, active organization isolation, CSRF and session
hardening, encrypted stored credentials, authenticated alert ingestion, a live
alert queue, SLA metrics, durable local job controls, approval-gated responder
execution, notification delivery, verified backups, non-root containers, CI
security checks, and reviewable self-learning promotion states.
The interactive Linux bootstrap can also configure local HTTPS using a private
CA, Nginx, loopback-only Gunicorn, and deployment-gated `ProxyFix` without a
public domain.

Local multi-user administration is now available. The bootstrap account is the
initial organization admin; it can issue one-time activation links, assign
manual roles, suspend memberships, and reset activation. Organization playbooks
can be converted into reviewable access-policy drafts. Only an explicit admin
approval activates policy-managed roles, allowed playbooks, and per-user target
scope. AI extraction never changes authorization by itself, and organization
credentials remain encrypted server-side rather than being distributed to users.

The full local test suite passes with **236 tests** (plus one OpenSSL integration
test skipped on the Windows development host). This is not a claim that a
specific environment is production-approved. Remaining deployment evidence and
scale-out work are tracked in
[`docs/PRODUCTION_ROADMAP.md`](docs/PRODUCTION_ROADMAP.md):

- Provide managed TLS and secret storage in the target environment.
- Run and record notification, restore, responder, staging soak, load, and rollback drills.
- Migrate to PostgreSQL/RLS and Redis/Celery before multi-host scaling.
- Pin third-party CI actions by immutable commit and curate a hashed Python lock file.

The self-learning subsystem creates redacted drafts and immutable capability
proposals. After independent human approval, the worker may publish a canary
skill, enable a catalogued responder, or run an allowlisted installer. It cannot
approve itself, execute free-form shell commands, or bypass environment gates.

---

## 1. The product goal (user's own words)

> "Base on the project state, if I add my Wazuh indexer and manager, will it be
> able to collect cases and alerts from Wazuh and use MISP and all other
> platforms for enrichment and resolve my Wazuh alerts and automatically
> generate the report. Also I want the copilot chat feature available at the
> dashboard, clickable so the user can chat with the AI about any alert and
> case; the AI answers based on access to all cases/alerts; the user can see the
> AI's thought process in the chat; and the AI should use the chat to get
> approval for any process it wants to execute — like the way I'm chatting with
> you right now."

The work was decomposed into 5 gaps, to be implemented sequentially:

| # | Gap | Status |
|---|-----|--------|
| 11 | Playbook approval steps block and wait for human approval **via chat** | ✅ Done |
| 13 | Bridge copilot chat actions to the **real enrichment clients** | ✅ Done |
| 14 | Wire **Cortex + PhishTank** into the enrichment dispatch | ✅ Done |
| 12 | **Wazuh alert poller** (optional background scheduler) | Done; authenticated controls, scoped credentials, and per-org watermarks |
| 15 | **Browser click-through test** of copilot + full pipeline | ⬜ Not started |

---

## 2. Architecture reminders (so you don't relearn them)

- **Flask** web app, **raw `sqlite3`** (NOT SQLAlchemy), Jinja2 templates,
  Tailwind via CDN. DB at `data/soc_operator.db`, `row_factory = sqlite3.Row`.
- **sqlite3 connections are thread-bound** — any worker thread must open its own
  `get_db()` connection. Commit before handing rows to another thread.
- **JobQueue** (`scripts/job_queue.py`): SQLite-backed persistent jobs, non-daemon
  worker threads. `create_job()` → `execute_job(job_id, callback)`.
- **Alert ingestion is consolidated** in `web/services/alert_ingest.py::ingest_alert_record()`.
  It normalizes → extracts IOCs → correlates cases → selects a playbook → queues
  a run. Both the manual `/api/ingest/alert` route and (soon) the poller call it.
- **PlaybookRunner** (`scripts/playbook_engine.py`): step types `llm`, `toolchain`,
  `rule`, `thehive`, `mitre_mapping`, `approval`, `report`. `_should_run(step)`
  consumes `when.condition` and skips the whole step when false.
- **EnrichmentClient** (`scripts/soc_client/enrichment.py`): aggregates VT /
  AbuseIPDB / Shodan / HybridAnalysis / **PhishTank** / **Cortex** / MISP.
  `enrich(ioc_type, value)` fans out to `enrich_ip/domain/hash/url`.
- **Config**: `web/app.py::build_platforms_toml()` renders `config/platforms.toml`
  from the DB (`credentials` + `platform_config` tables). Clients are built by
  `scripts/orchestrator.py::build_clients(config)` after credentials are loaded
  into `os.environ`.
- **Copilot**: `web/templates/copilot_widget.html` is `{% include %}`d by
  `base.html`, so it's on every authenticated page. It talks to
  `web/routes/chat.py`. The **global/dashboard** thread uses the sentinel
  `case_id = 0`. Approvals reuse the `chat_actions` table.
- **LLM**: GPT-5.6 chat via `OPENAI_API_KEY`.
- **Windows dev env**: interpreter is `.venv/Scripts/python.exe`. Read files with
  `encoding='utf-8'`. Terminal print of non-ASCII (✓, emoji) crashes on cp1252 —
  use ASCII in `print()`.

---

## 3. What was implemented this round (details)

### #11 — Playbook approval → chat blocking (DONE)
- `scripts/playbook_engine.py`: `PlaybookRunner.__init__` accepts
  `approval_handler`. `_run_approval` calls it and blocks; the runner **halts**
  (breaks the step loop) on `rejected`/`timeout`.
- `scripts/orchestrator.py`: `execute_playbook(..., approval_handler=None)` passes
  it through.
- `web/app.py::_execute_run_job`: builds `make_approval_handler(run_id)` and
  passes it to `execute_playbook`.
- `web/services/approvals.py` (NEW): `make_approval_handler(run_id)` returns a
  handler that, when the playbook hits an approval step, posts an assistant
  message + a `chat_actions` row (`action_type='playbook_approval'`) into the
  **global copilot thread (case_id=0)**, then polls every 1s until a human
  approves/rejects via the existing copilot endpoints. 30-min timeout.
- `web/templates/copilot_widget.html`: polls every 5s, badges the launcher with
  the pending-approval count so requests surface even when the panel is closed.

### #13 — Copilot actions → real enrichment (DONE)
- `web/services/chat.py::execute_enrichment(ioc_type, value)` builds clients and
  calls `EnrichmentClient.enrich`. Added an `"enrichment"` action_type end-to-end.
- `web/routes/chat.py::chat_action_approve`: handles `action_type == "enrichment"`.
- Copilot widget renders enrichment results (platforms + JSON) vs tool output.

### #14 — Cortex + PhishTank enrichment (DONE)
- `scripts/soc_client/enrichment.py`:
  - `_init_clients` builds `phishtank` (keyless ok) and `cortex` clients.
  - `_phishtank_lookup(url)` → wired into `enrich_url`.
  - `_cortex_enrich(data_type, value)` — bounded: runs ≤ `CORTEX_MAX_ANALYZERS`
    (default 3) analyzers, polls `get_job` within `CORTEX_POLL_TIMEOUT` (default
    25s); analyzers still running at timeout return `status: "running"`. Wired
    into `enrich_ip/domain/hash/url`.
- `scripts/playbook_engine.py`: toolchain dispatch gate now includes `"cortex"`,
  `"phishtank"`.
- `scripts/orchestrator.py::build_clients`: enrichment client is built when any of
  `[... phishtank, cortex, misp]` are enabled.
- `web/app.py`: `KEYLESS_PLATFORMS = {"phishtank"}`; PhishTank added to
  `PLATFORM_DEFAULTS`, `PLATFORM_CREDENTIAL_KEYS` (optional key), and
  `build_platforms_toml` (enabled on its config flag, not gated on a credential).
  `save_platform_settings` reads a `phishtank_enabled` checkbox.
- `web/templates/credentials.html`: PhishTank card (Enable checkbox + optional key).

### #12 — Wazuh poller (PARTIAL — see §4)
- `web/services/wazuh_poller.py` (NEW): full `WazuhAlertPoller` class —
  `start()/stop()/status()/poll_once()`, watermark persistence in a new
  `poller_state` table, dedup by `source_alert_id`, first-run baseline to "now"
  (override with `WAZUH_POLL_BACKFILL=1`). Module-level `get_poller()` singleton.
- `web/app.py`: added Wazuh **Indexer** basic-auth config plumbing —
  `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` in `PLATFORM_CREDENTIAL_KEYS`,
  and `build_platforms_toml` now emits a `[platforms.wazuh_indexer]` block with
  `username_env`/`password_env` (enabled only when base_url + both creds exist).

---

## 4. Historical pre-hardening notes

The subsections below describe the August 2026 state and are retained only as
implementation history. The poller wiring described as missing in 4a is now
implemented. Use the current release status above and the production roadmap
for remaining work.

### 4a. Finish #12 — wire the poller (est. small)

The poller class is done but **imported by nothing**. To activate it:

1. **Credentials UI** — `web/templates/credentials.html`: the "Wazuh Indexer" card
   currently only renders a Base URL field (its `key_name` is `''`). Add two
   inputs so the operator can enter indexer creds:
   - `name="WAZUH_INDEXER_USER"` (text)
   - `name="WAZUH_INDEXER_PASSWORD"` (password)
   Easiest: pull "Wazuh Indexer" out of the generic `{% for %}` loop and give it a
   dedicated card (like the PhishTank card just above the loop), with URL + user +
   password fields. `save_platform_settings` already persists these key names.

2. **Control routes** — add to `web/routes/features.py` (blueprint `features_bp`,
   `_login_required` already defined there). Suggested:
   ```python
   @features_bp.post("/api/wazuh/poller/start")
   @_login_required
   def wazuh_poller_start():
       from web.services.wazuh_poller import get_poller
       started = get_poller().start()
       return jsonify({"ok": True, "started": started, "status": get_poller().status()})

   @features_bp.post("/api/wazuh/poller/stop")
   @_login_required
   def wazuh_poller_stop():
       from web.services.wazuh_poller import get_poller
       get_poller().stop()
       return jsonify({"ok": True, "status": get_poller().status()})

   @features_bp.get("/api/wazuh/poller/status")
   @_login_required
   def wazuh_poller_status():
       from web.services.wazuh_poller import get_poller
       return jsonify({"ok": True, "status": get_poller().status()})

   @features_bp.post("/api/wazuh/poller/poll-once")
   @_login_required
   def wazuh_poller_poll_once():
       from web.services.wazuh_poller import get_poller
       return jsonify(get_poller().poll_once())   # {ok, ingested, skipped, error}
   ```

3. **Optional auto-start** — in `web/app.py`'s `if __name__ == "__main__":` block
   (after `init_db()`), start the poller only when opted in:
   ```python
   import os
   if os.environ.get("WAZUH_POLL_ENABLED", "").lower() in {"1","true","yes","on"}:
       from web.services.wazuh_poller import get_poller
       get_poller().start()
   ```
   Keep it **opt-in** — do not start by default.

4. **(Optional) Dashboard toggle** — a small Start/Stop/Status control that hits
   the routes above. Not required for functionality.

5. **Verify** without a live Wazuh: monkeypatch `get_poller()._build_indexer_client`
   to return a fake client whose `search_alerts` returns a canned ES response
   (`{"hits":{"hits":[{"_id":"abc","_source":{...wazuh doc...}}]}}`), call
   `poll_once()` twice, and assert the 2nd call skips (dedup) and a row lands in
   `alerts`. The `_source` shape flows straight through `_normalize_wazuh`
   (top-level `rule`, `data`, `agent`, `timestamp`, `full_log`).

### 4b. #15 — Browser click-through test (needs a live `OPENAI_API_KEY`)

Run the app and manually exercise, ideally with the Browser tools:
```bash
.venv/Scripts/python.exe -m web.app
```
(or set up `.claude/launch.json` and use the preview tools). Then:
- Log in / complete `/setup` if no user exists.
- Confirm the 💬 Copilot launcher appears on the dashboard and opens.
- Send a message; confirm the answer renders, the collapsible **🧠 Thought process**
  shows, and a suggested action (enrichment) appears with Approve/Reject.
- Approve an enrichment action; confirm results render in the chat.
- Trigger a run whose playbook has an `approval` step; confirm the copilot badges
  a pending approval, and approving it **unblocks** the playbook (check the run
  completes; rejecting halts it).
- Ingest a Wazuh-shaped alert via `POST /api/ingest/alert` (source `wazuh`) and
  confirm it selects a playbook, runs, and produces a case + report.

---

## 5. Verification commands

```bash
# AST-check + unit tests (must stay green)
.venv/Scripts/python.exe -m pytest tests/test_playbook_engine.py tests/test_integration.py -q
```
All **33 tests pass** as of this commit. Enrichment additions were verified with a
mocked PhishTank + Cortex client (both paths return results and appear under
`results["phishtank"]` / `results["cortex"]`).

---

## 6. Known limitations / watch-outs

- **`build_platforms_toml` only emits platforms in its key map.** If you add a new
  platform, add it in three places: `PLATFORM_DEFAULTS`, `PLATFORM_CREDENTIAL_KEYS`,
  and the `key_name` map inside `build_platforms_toml` (plus the `build_clients`
  enrichment trigger list and the credentials template).
- **No unique constraint on `alerts(source, source_alert_id)`** — dedup is done in
  the poller in Python. If you add another polling source, replicate the dedup or
  add a DB unique index.
- **Cortex enrichment can block up to `CORTEX_POLL_TIMEOUT` (25s)** per observable
  in the request/worker thread. Tune via env if analyzers are slow.
- **Approvals route to the global thread (case_id=0)** because the case doesn't
  exist yet while the playbook runs. This is intentional and matches the
  dashboard-wide copilot.
