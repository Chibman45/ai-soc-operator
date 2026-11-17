"""Isolated Flask server and browser fixtures for Phase 5 acceptance tests."""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest
from playwright.sync_api import Browser, BrowserContext, Page
from werkzeug.serving import make_server

import web.app as app_module
import web.routes.admin as admin_routes
import web.routes.assurance as assurance_routes
import web.routes.documents as document_routes
import web.routes.features as feature_routes
import web.security as security_module
from scripts.job_queue import JobQueue

TEST_USERS = {
    "admin": "Admin-browser-password-123!",
    "analyst": "Analyst-browser-password-123!",
    "viewer": "Viewer-browser-password-123!",
}


def pytest_collection_modifyitems(items):
    """Keep browser installation isolated to the dedicated acceptance job."""
    if os.environ.get("AI_SOC_RUN_BROWSER_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="set AI_SOC_RUN_BROWSER_TESTS=1 in the Playwright acceptance job")
    for item in items:
        if item.fspath.dirname == str(Path(__file__).parent):
            item.add_marker(skip)


def _seed_database(database: Path) -> dict[str, int]:
    app_module.init_db()
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    org_id = int(conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()["id"])

    user_ids: dict[str, int] = {}
    for username, password in TEST_USERS.items():
        cursor = conn.execute(
            """
            INSERT INTO users
                (username, password_hash, default_org_id, must_change_password, session_version)
            VALUES (?, ?, ?, 0, 0)
            """,
            (username, app_module.hash_password(password), org_id),
        )
        user_id = int(cursor.lastrowid)
        user_ids[username] = user_id
        conn.execute(
            "INSERT INTO organization_memberships (org_id, user_id, status) VALUES (?, ?, 'active')",
            (org_id, user_id),
        )

    role_ids = {
        row["name"]: int(row["id"])
        for row in conn.execute("SELECT id, name FROM roles WHERE name IN ('admin', 'analyst', 'read_only')")
    }
    for username, role_name in (("admin", "admin"), ("analyst", "analyst"), ("viewer", "read_only")):
        conn.execute(
            "INSERT INTO user_roles (user_id, role_id, org_id, source) VALUES (?, ?, ?, 'manual')",
            (user_ids[username], role_ids[role_name], org_id),
        )

    # The approver must differ from the requester; the seeded run enforces that control.
    conn.execute(
        """
        INSERT INTO runs (id, org_id, requested_by, playbook, alert_file, status)
        VALUES (1, ?, ?, 'identity-compromise.yaml', 'demo/browser-alert.json', 'awaiting_approval')
        """,
        (org_id, user_ids["analyst"]),
    )
    conn.execute(
        """
        INSERT INTO cases
            (id, org_id, run_id, title, severity, status, summary, opened_at, row_version)
        VALUES (1, ?, 1, 'Approval review case', 'high', 'open',
                'A browser acceptance case awaiting human approval.', CURRENT_TIMESTAMP, 0)
        """,
        (org_id,),
    )
    conn.execute(
        """
        INSERT INTO cases
            (id, org_id, title, severity, status, summary, opened_at, row_version)
        VALUES (2, ?, 'Unassigned investigation', 'medium', 'open',
                'A browser acceptance case available for analyst claim.', CURRENT_TIMESTAMP, 0)
        """,
        (org_id,),
    )
    conn.execute(
        """
        INSERT INTO alerts
            (org_id, source, source_alert_id, title, severity, raw_payload,
             normalized_payload, status, selected_playbook)
        VALUES (?, 'wazuh', 'browser-alert-1', 'Repeated SSH authentication failures',
                'high', '{}', '{}', 'queued', 'identity-compromise.yaml')
        """,
        (org_id,),
    )
    conn.commit()
    conn.close()
    return {"org_id": org_id, **{f"{name}_id": value for name, value in user_ids.items()}}


@pytest.fixture(scope="module")
def soc_server(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("browser-acceptance") / "soc-root"
    database = root / "data" / "soc_operator.db"
    (root / "data").mkdir(parents=True)
    (root / "playbooks").mkdir()
    (root / "evidence").mkdir()

    with ExitStack() as patches:
        patches.enter_context(patch.object(app_module, "ROOT", root))
        patches.enter_context(patch.object(app_module, "DB_PATH", database))
        patches.enter_context(patch.object(security_module, "DB_PATH", database))
        patches.enter_context(patch.object(feature_routes, "ROOT", root))
        patches.enter_context(patch.object(document_routes, "ROOT", root))
        patches.enter_context(patch.object(document_routes, "DB_PATH", database))
        patches.enter_context(patch.object(admin_routes, "ROOT", root))
        patches.enter_context(patch.object(admin_routes, "DB_PATH", database))
        patches.enter_context(patch.object(assurance_routes, "DB_PATH", database))
        patches.enter_context(patch.object(app_module, "job_queue", JobQueue(database)))
        # Browser acceptance must not append synthetic identities or actions to the real audit trail.
        for module in (app_module, security_module, feature_routes, document_routes, admin_routes):
            patches.enter_context(patch.object(module, "audit", lambda *_args, **_kwargs: None))

        app_module.app.config.update(TESTING=True)
        seeded = _seed_database(database)
        server = make_server("127.0.0.1", 0, app_module.app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield {
                "base_url": f"http://127.0.0.1:{server.server_port}",
                "database": database,
                "root": root,
                **seeded,
            }
        finally:
            server.shutdown()
            thread.join(timeout=5)


@pytest.fixture()
def context(browser: Browser) -> BrowserContext:
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    # Tailwind is presentation-only; blocking its CDN keeps acceptance deterministic and offline-capable.
    context.route("https://cdn.tailwindcss.com/**", lambda route: route.abort())
    yield context
    context.close()


@pytest.fixture()
def page(context: BrowserContext) -> Page:
    page = context.new_page()
    page.set_default_timeout(5_000)
    yield page
    page.close()


def login(page: Page, base_url: str, username: str) -> None:
    page.goto(f"{base_url}/login")
    page.locator('input[name="username"]').fill(username)
    page.locator('input[name="password"]').fill(TEST_USERS[username])
    page.get_by_role("button", name="Sign In").click()
    page.wait_for_url(f"{base_url}/")

