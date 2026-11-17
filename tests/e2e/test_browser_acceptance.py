"""Phase 5 browser acceptance for the operator's critical local workflows."""

from __future__ import annotations

import re
import sqlite3

from playwright.sync_api import Page, expect

from .conftest import login


def _database_value(database, query: str, params: tuple = ()):
    conn = sqlite3.connect(database)
    try:
        row = conn.execute(query, params).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def test_login_dashboard_and_alert_queue(page: Page, soc_server):
    login(page, soc_server["base_url"], "admin")

    expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()
    expect(page.get_by_role("heading", name="Alert Queue")).to_be_visible()
    expect(page.get_by_text("Repeated SSH authentication failures")).to_be_visible()
    expect(page.locator("#alert-queue").get_by_text("identity-compromise.yaml", exact=True)).to_be_visible()


def test_admin_assigns_case_to_an_active_member(page: Page, soc_server):
    login(page, soc_server["base_url"], "admin")
    page.get_by_role("link", name="Cases").click()

    assignment = page.get_by_label("Assign case 1")
    assignment.select_option(str(soc_server["analyst_id"]))
    page.wait_for_load_state("networkidle")

    expect(page.get_by_label("Assign case 1")).to_have_value(str(soc_server["analyst_id"]))
    assert _database_value(
        soc_server["database"], "SELECT assignee_id FROM cases WHERE id = 1"
    ) == soc_server["analyst_id"]


def test_analyst_claims_an_unassigned_case(page: Page, soc_server):
    login(page, soc_server["base_url"], "analyst")
    page.get_by_role("link", name="Cases").click()

    case_row = page.get_by_role("row").filter(has_text="Unassigned investigation")
    case_row.get_by_role("button", name="Claim").click()
    page.wait_for_load_state("networkidle")

    expect(page.get_by_role("row").filter(has_text="Unassigned investigation")).to_contain_text("You · release")
    assert _database_value(
        soc_server["database"], "SELECT assignee_id FROM cases WHERE id = 2"
    ) == soc_server["analyst_id"]


def test_admin_approves_a_run_requested_by_another_user(page: Page, soc_server):
    login(page, soc_server["base_url"], "admin")
    page.goto(f"{soc_server['base_url']}/cases/1")

    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Approve Actions").click()
    page.wait_for_load_state("networkidle")

    assert _database_value(
        soc_server["database"], "SELECT status FROM runs WHERE id = 1"
    ) == "approved"
    assert _database_value(
        soc_server["database"],
        "SELECT COUNT(*) FROM activity_log WHERE run_id = 1 AND step = 'approval' AND status = 'done'",
    ) == 1


def test_playbook_upload_stops_at_human_review_preview(page: Page, soc_server, tmp_path):
    upload = tmp_path / "browser-reviewed-playbook.yaml"
    upload.write_text(
        "id: browser-reviewed\nname: Browser reviewed\nsteps:\n  - id: report\n    type: report\n",
        encoding="utf-8",
    )
    login(page, soc_server["base_url"], "admin")
    page.get_by_role("link", name="Playbooks").click()

    page.locator('input[name="playbook"][type="file"]').set_input_files(upload)
    page.get_by_role("button", name="Upload").click()

    expect(page).to_have_url(re.compile(r"/documents/\d+/preview$"))
    expect(page.get_by_role("heading", name="Review extracted document")).to_be_visible()
    expect(page.get_by_text("AI analysis has not run yet.")).to_be_visible()
    expect(page.get_by_text("browser-reviewed-playbook.yaml")).to_be_visible()
    assert not (soc_server["root"] / "playbooks" / "browser-reviewed-playbook.yaml").exists()
    assert _database_value(
        soc_server["database"],
        "SELECT status FROM document_ingestions WHERE source_name = ?",
        ("browser-reviewed-playbook.yaml",),
    ) == "preview"


def test_read_only_user_is_denied_administration(page: Page, soc_server):
    login(page, soc_server["base_url"], "viewer")

    expect(page.get_by_role("link", name="Users")).to_have_count(0)
    response = page.goto(f"{soc_server['base_url']}/admin/users")
    assert response is not None
    assert response.status == 403
    expect(page.get_by_text("Forbidden")).to_be_visible()

