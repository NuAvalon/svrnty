#!/usr/bin/env python3
"""svrnty Failure Model Simulations — Red Team
Tests how the app behaves under adversarial/failure conditions.

Scenarios:
  FM-1: KEY_LOSS — keys store emptied, identity intact
  FM-2: CORRUPT_IDENTITY — malformed identity record in IndexedDB
  FM-3: ORPHAN_CONTACTS — identity deleted, contacts remain
  FM-4: NETWORK_PARTITION — relay server unreachable during share
  FM-5: RELAY_TIMEOUT — slow relay responses during import
  FM-6: IDENTITY_COLLISION — duplicate fingerprint in contacts

Each test creates a fresh browser context, sets up the failure condition
via IndexedDB manipulation, and checks the app's behavior.

Requires: playwright, dev server on localhost:3333
Author: Flint | 2026-06-19
"""
import json
import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, Page, BrowserContext

BASE = os.environ.get("SVRNTY_TEST_URL", "http://localhost:3333")
SHOTS = Path("/tmp/svrnty_failure_models")
RESULTS = []


def shot(page: Page, name: str, prefix: str = "") -> str:
    SHOTS.mkdir(parents=True, exist_ok=True)
    tag = f"{prefix}_" if prefix else ""
    path = SHOTS / f"{tag}{name}.png"
    page.screenshot(path=str(path))
    return str(path)


def record(name: str, passed: bool, detail: str = ""):
    status = "PASS" if passed else "FAIL"
    RESULTS.append((name, passed, detail))
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail else ""), flush=True)


def create_identity(page: Page, name: str, email: str, prefix: str) -> bool:
    """Create identity via UI. Returns True if dashboard loads."""
    resp = page.goto(BASE, wait_until="networkidle")
    if not resp or resp.status != 200:
        return False

    forge_btn = page.locator("text=Start")
    if not forge_btn.is_visible(timeout=5000):
        return False
    forge_btn.click()
    page.wait_for_timeout(500)

    page.locator('input[placeholder="Your name"]').fill(name)
    page.locator('input[placeholder="your@email.com"]').fill(email)

    page.locator('button:has-text("Start")').last.click()
    page.wait_for_timeout(8000)

    return (
        page.locator('button:has-text("Galaxy")').first.is_visible() or
        page.locator('text=constellation').first.is_visible()
    )


def idb_eval(page: Page, js: str) -> any:
    """Run JS against IndexedDB in page context. Returns result."""
    return page.evaluate(js)


def delete_idb_store_contents(page: Page, store_name: str):
    """Clear all records from an IndexedDB object store."""
    idb_eval(page, f"""
        () => new Promise((resolve, reject) => {{
            const req = indexedDB.open('svrnty', 2);
            req.onsuccess = () => {{
                const db = req.result;
                const tx = db.transaction('{store_name}', 'readwrite');
                tx.objectStore('{store_name}').clear();
                tx.oncomplete = () => {{ db.close(); resolve(true); }};
                tx.onerror = () => {{ db.close(); reject(tx.error); }};
            }};
            req.onerror = () => reject(req.error);
        }})
    """)


def inject_idb_record(page: Page, store_name: str, record_data: dict):
    """Put a record into an IndexedDB object store."""
    data_json = json.dumps(record_data)
    idb_eval(page, f"""
        () => new Promise((resolve, reject) => {{
            const req = indexedDB.open('svrnty', 2);
            req.onsuccess = () => {{
                const db = req.result;
                const tx = db.transaction('{store_name}', 'readwrite');
                tx.objectStore('{store_name}').put({data_json});
                tx.oncomplete = () => {{ db.close(); resolve(true); }};
                tx.onerror = () => {{ db.close(); reject(tx.error); }};
            }};
            req.onerror = () => reject(req.error);
        }})
    """)


def get_idb_records(page: Page, store_name: str) -> list:
    """Get all records from an IndexedDB object store."""
    return idb_eval(page, f"""
        () => new Promise((resolve, reject) => {{
            const req = indexedDB.open('svrnty', 2);
            req.onsuccess = () => {{
                const db = req.result;
                const tx = db.transaction('{store_name}', 'readonly');
                const getReq = tx.objectStore('{store_name}').getAll();
                getReq.onsuccess = () => {{ db.close(); resolve(getReq.result); }};
                getReq.onerror = () => {{ db.close(); reject(getReq.error); }};
            }};
            req.onerror = () => reject(req.error);
        }})
    """)


# ── FM-1: KEY_LOSS ──────────────────────────────────────────────

def test_key_loss(browser):
    """Delete keys from IndexedDB but keep identity. App should show
    the gate/recovery screen, not crash or show blank dashboard."""
    print("\n[FM-1] KEY_LOSS — keys deleted, identity intact", flush=True)
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    js_errors = []
    page.on("pageerror", lambda err: js_errors.append(str(err)))

    ok = create_identity(page, "KeyLoss User", "keyloss@test.local", "fm1")
    if not ok:
        record("FM-1: Setup", False, "Could not create identity")
        ctx.close()
        return

    # Capture fingerprint before corruption
    fp = idb_eval(page, """
        () => new Promise((resolve, reject) => {
            const req = indexedDB.open('svrnty', 2);
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction('settings', 'readonly');
                const getReq = tx.objectStore('settings').get('active_fingerprint');
                getReq.onsuccess = () => { db.close(); resolve(getReq.result?.value || null); };
                getReq.onerror = () => { db.close(); reject(getReq.error); };
            };
            req.onerror = () => reject(req.error);
        })
    """)
    record("FM-1: Identity created", fp is not None, f"fp={fp[:12]}..." if fp else "no fp")

    # Delete keys store — simulating key loss
    delete_idb_store_contents(page, "keys")
    delete_idb_store_contents(page, "pq_keys")
    shot(page, "01_keys_deleted", "fm1")

    # Reload — app should detect missing keys
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(3000)
    shot(page, "02_after_reload", "fm1")

    # Check: app should NOT show a functional dashboard without keys
    # It should show gate screen, error, or recovery prompt
    has_dashboard = (
        page.locator('button:has-text("Galaxy")').first.is_visible() or
        page.locator('text=constellation').first.is_visible()
    )
    has_gate = page.locator("text=Start").is_visible(timeout=2000)
    has_error = page.locator('text=error').first.is_visible(timeout=1000)

    # Worst case: dashboard loads without keys = security issue
    if has_dashboard:
        # Check if signing operations would fail
        record("FM-1: Key loss detected", False,
               "SECURITY: Dashboard loaded without keys — user may attempt operations that silently fail")
    elif has_gate or has_error:
        record("FM-1: Key loss detected", True,
               "Gate/error shown — user guided to recovery")
    else:
        record("FM-1: Key loss detected", False,
               "Neither dashboard nor gate — blank/stuck state")

    # Check for JS crashes
    critical = [e for e in js_errors if "TypeError" in e or "ReferenceError" in e]
    record("FM-1: No crash on key loss", len(critical) == 0,
           f"{len(critical)} JS errors: {critical[0][:80]}" if critical else "Clean")

    ctx.close()


# ── FM-2: CORRUPT_IDENTITY ──────────────────────────────────────

def test_corrupt_identity(browser):
    """Inject a malformed identity record. App should handle gracefully."""
    print("\n[FM-2] CORRUPT_IDENTITY — malformed identity record", flush=True)
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    js_errors = []
    page.on("pageerror", lambda err: js_errors.append(str(err)))

    # Navigate to create the DB schema
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(2000)

    # Inject corrupt identity — missing required fields
    corrupt_fp = "deadbeef12345678"
    inject_idb_record(page, "identities", {
        "fingerprint": corrupt_fp,
        "data": {"version": "corrupt", "identity": None},  # missing name, keys, etc.
        "created_at": "not-a-date",
    })
    inject_idb_record(page, "settings", {
        "key": "active_fingerprint",
        "value": corrupt_fp,
    })
    shot(page, "01_corrupted", "fm2")

    # Reload with corrupt state
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(3000)
    shot(page, "02_after_reload", "fm2")

    # App should either show gate (identity invalid) or error — not crash
    has_gate = page.locator("text=Start").is_visible(timeout=2000)
    has_recover = page.locator("text=Restore").is_visible(timeout=1000)

    critical = [e for e in js_errors if "TypeError" in e or "ReferenceError" in e or "Cannot read" in e]
    record("FM-2: No crash on corrupt identity", len(critical) == 0,
           f"{len(critical)} JS errors: {critical[0][:100]}" if critical else "Clean")
    record("FM-2: Graceful degradation", has_gate or has_recover,
           "Gate/restore shown" if (has_gate or has_recover) else "No recovery path visible")

    ctx.close()


# ── FM-3: ORPHAN_CONTACTS ──────────────────────────────────────

def test_orphan_contacts(browser):
    """Delete identity but leave contacts in IndexedDB. App should not
    crash and should show gate screen."""
    print("\n[FM-3] ORPHAN_CONTACTS — identity deleted, contacts remain", flush=True)
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    js_errors = []
    page.on("pageerror", lambda err: js_errors.append(str(err)))

    ok = create_identity(page, "Orphan User", "orphan@test.local", "fm3")
    if not ok:
        record("FM-3: Setup", False, "Could not create identity")
        ctx.close()
        return

    # Get fingerprint, then inject a contact, then delete identity
    fp = idb_eval(page, """
        () => new Promise((resolve, reject) => {
            const req = indexedDB.open('svrnty', 2);
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction('settings', 'readonly');
                const getReq = tx.objectStore('settings').get('active_fingerprint');
                getReq.onsuccess = () => { db.close(); resolve(getReq.result?.value || null); };
                getReq.onerror = () => { db.close(); reject(getReq.error); };
            };
            req.onerror = () => reject(req.error);
        })
    """)

    # Inject a fake contact owned by this identity
    inject_idb_record(page, "contacts", {
        "id": "orphan-contact-001",
        "fingerprint": "cafebabe00000001",
        "owner_fingerprint": fp,
        "name": "Ghost Contact",
        "email": "ghost@nowhere.local",
        "public_key": "fake-key",
        "trust_level": "verified",
        "added_at": "2026-01-01T00:00:00Z",
    })

    # Delete identity + keys but keep contacts and active_fingerprint setting
    delete_idb_store_contents(page, "identities")
    delete_idb_store_contents(page, "keys")
    delete_idb_store_contents(page, "pq_keys")
    shot(page, "01_orphaned", "fm3")

    # Reload
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(3000)
    shot(page, "02_after_reload", "fm3")

    has_gate = page.locator("text=Start").is_visible(timeout=2000)
    has_restore = page.locator("text=Restore").is_visible(timeout=1000)

    critical = [e for e in js_errors if "TypeError" in e or "ReferenceError" in e]
    record("FM-3: No crash on orphan contacts", len(critical) == 0,
           f"{len(critical)} JS errors: {critical[0][:100]}" if critical else "Clean")
    record("FM-3: Gate shown (identity missing)", has_gate or has_restore,
           "Recovery path available" if (has_gate or has_restore) else "Stuck state")

    ctx.close()


# ── FM-4: NETWORK_PARTITION ────────────────────────────────────

def test_network_partition(browser):
    """Block relay API calls. Share link generation should fail with
    a user-visible error, not hang or crash."""
    print("\n[FM-4] NETWORK_PARTITION — relay server blocked", flush=True)
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    js_errors = []
    page.on("pageerror", lambda err: js_errors.append(str(err)))

    ok = create_identity(page, "Partition User", "partition@test.local", "fm4")
    if not ok:
        record("FM-4: Setup", False, "Could not create identity")
        ctx.close()
        return
    record("FM-4: Identity created", True)

    # Block all relay API calls (route.abort simulates network failure)
    def block_relay(route):
        url = route.request.url
        if "/relay" in url or "/api/" in url:
            route.abort("connectionrefused")
        else:
            route.continue_()

    page.route("**/*", block_relay)

    # Try to share — go to Identity/Contacts and click Share
    id_tab = page.locator('button:has-text("IDENTITY")')
    if id_tab.count() > 0:
        id_tab.first.click()
        page.wait_for_timeout(1000)

    share_btn = page.locator('button:has-text("Share"), button:has-text("share")')
    if share_btn.count() == 0:
        contacts_tab = page.locator('button:has-text("CONTACTS")')
        if contacts_tab.count() > 0:
            contacts_tab.first.click()
            page.wait_for_timeout(500)
            share_btn = page.locator('button:has-text("Share"), button:has-text("share")')

    if share_btn.count() == 0:
        record("FM-4: Share button found", False, "No share button — can't test partition")
        ctx.close()
        return

    share_btn.first.click()
    page.wait_for_timeout(1000)

    # Click Short Code / Link tab
    link_tab = page.locator('text=Short Code')
    if link_tab.count() == 0:
        link_tab = page.locator('text=Link')
    if link_tab.count() > 0:
        link_tab.first.click()
        page.wait_for_timeout(500)

    gen_btn = page.locator('button:has-text("Generate Link")')
    if gen_btn.count() > 0:
        gen_btn.first.click()
        page.wait_for_timeout(5000)  # Wait for timeout to trigger
        shot(page, "01_partition_result", "fm4")

        # Check: should show error, not a link
        has_error = (
            page.locator('text=error').first.is_visible(timeout=2000) or
            page.locator('text=failed').first.is_visible(timeout=1000) or
            page.locator('text=unavailable').first.is_visible(timeout=1000) or
            page.locator('text=offline').first.is_visible(timeout=1000)
        )
        has_code = page.locator("code").count() > 0

        if has_code and not has_error:
            record("FM-4: Partition detected", False,
                   "Generated a code despite network block — may be using cached/local relay")
        elif has_error:
            record("FM-4: Partition detected", True, "Error shown to user")
        else:
            record("FM-4: Partition detected", False, "No error and no code — silent failure")
    else:
        record("FM-4: Generate button found", False, "No generate button visible")

    critical = [e for e in js_errors if "TypeError" in e or "ReferenceError" in e]
    record("FM-4: No crash on partition", len(critical) == 0,
           f"{len(critical)} JS errors" if critical else "Clean")

    page.unroute("**/*")
    ctx.close()


# ── FM-5: RELAY_TIMEOUT ────────────────────────────────────────

def test_relay_timeout(browser):
    """Slow relay responses (30s delay). Import page should show
    loading state and eventually timeout gracefully."""
    print("\n[FM-5] RELAY_TIMEOUT — slow relay responses", flush=True)

    # Need two contexts — Alice (normal) creates link, Bob (slow) imports
    alice_ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    bob_ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    alice = alice_ctx.new_page()
    bob = bob_ctx.new_page()
    bob_errors = []
    bob.on("pageerror", lambda err: bob_errors.append(str(err)))

    # Alice creates identity and share link (normal speed)
    alice_ok = create_identity(alice, "Alice Slow", "alice.slow@test.local", "fm5_alice")
    if not alice_ok:
        record("FM-5: Setup", False, "Could not create Alice identity")
        alice_ctx.close()
        bob_ctx.close()
        return

    # Get share link from Alice
    import re
    id_tab = alice.locator('button:has-text("IDENTITY")')
    if id_tab.count() > 0:
        id_tab.first.click()
        alice.wait_for_timeout(1000)

    share_btn = alice.locator('button:has-text("Share"), button:has-text("share")')
    if share_btn.count() == 0:
        ct = alice.locator('button:has-text("CONTACTS")')
        if ct.count() > 0:
            ct.first.click()
            alice.wait_for_timeout(500)
            share_btn = alice.locator('button:has-text("Share"), button:has-text("share")')

    if share_btn.count() == 0:
        record("FM-5: Setup", False, "No share button")
        alice_ctx.close()
        bob_ctx.close()
        return

    share_btn.first.click()
    alice.wait_for_timeout(1000)
    link_tab = alice.locator('text=Short Code')
    if link_tab.count() == 0:
        link_tab = alice.locator('text=Link')
    if link_tab.count() > 0:
        link_tab.first.click()
        alice.wait_for_timeout(500)
    gen_btn = alice.locator('button:has-text("Generate Link")')
    if gen_btn.count() == 0:
        record("FM-5: Setup", False, "No generate button")
        alice_ctx.close()
        bob_ctx.close()
        return

    gen_btn.first.click()
    alice.wait_for_timeout(3000)
    code_el = alice.locator("code")
    if code_el.count() == 0:
        record("FM-5: Setup", False, "No code element after generation")
        alice_ctx.close()
        bob_ctx.close()
        return

    link_text = code_el.first.inner_text()
    match = re.search(r'/c/([A-Za-z0-9]+)#(.+)', link_text)
    if not match:
        record("FM-5: Setup", False, f"Could not parse link: {link_text[:50]}")
        alice_ctx.close()
        bob_ctx.close()
        return

    code, key_frag = match.group(1), match.group(2)
    record("FM-5: Alice link created", True, f"code={code}")

    # Bob creates identity first
    bob_ok = create_identity(bob, "Bob Slow", "bob.slow@test.local", "fm5_bob")
    if not bob_ok:
        record("FM-5: Setup", False, "Could not create Bob identity")
        alice_ctx.close()
        bob_ctx.close()
        return

    # Add 15-second delay to relay API calls for Bob
    def slow_relay(route):
        url = route.request.url
        if "/relay" in url or f"/c/{code}" in url:
            import threading
            # Fulfill after delay to simulate timeout
            def delayed():
                try:
                    route.abort("timedout")
                except Exception:
                    pass
            timer = threading.Timer(15.0, delayed)
            timer.start()
        else:
            route.continue_()

    bob.route("**/*", slow_relay)

    # Bob navigates to relay link
    bob.goto(f"{BASE}/c/{code}#{key_frag}", wait_until="domcontentloaded", timeout=5000)
    bob.wait_for_timeout(3000)
    shot(bob, "01_slow_loading", "fm5")

    # Check: should show loading indicator, not blank/crashed
    has_loading = (
        bob.locator('text=Loading').first.is_visible(timeout=2000) or
        bob.locator('text=Decrypting').first.is_visible(timeout=1000) or
        bob.locator('[role="progressbar"]').count() > 0 or
        bob.locator('.animate-spin, .animate-pulse').count() > 0
    )
    has_error = (
        bob.locator('text=unavailable').first.is_visible(timeout=1000) or
        bob.locator('text=timed out').first.is_visible(timeout=1000) or
        bob.locator('text=error').first.is_visible(timeout=1000)
    )

    if has_loading or has_error:
        record("FM-5: Timeout handled", True,
               "Loading/error state shown" + (" (loading)" if has_loading else " (error)"))
    else:
        record("FM-5: Timeout handled", False, "No loading or error indicator visible")

    critical = [e for e in bob_errors if "TypeError" in e or "ReferenceError" in e]
    record("FM-5: No crash on timeout", len(critical) == 0,
           f"{len(critical)} JS errors" if critical else "Clean")

    bob.unroute("**/*")
    alice_ctx.close()
    bob_ctx.close()


# ── FM-6: IDENTITY_COLLISION ───────────────────────────────────

def test_identity_collision(browser):
    """Two contacts with the same fingerprint. The IndexedDB unique index
    on contacts.fingerprint should prevent silent overwrites."""
    print("\n[FM-6] IDENTITY_COLLISION — duplicate fingerprint in contacts", flush=True)
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    js_errors = []
    page.on("pageerror", lambda err: js_errors.append(str(err)))

    ok = create_identity(page, "Collision User", "collision@test.local", "fm6")
    if not ok:
        record("FM-6: Setup", False, "Could not create identity")
        ctx.close()
        return

    fp = idb_eval(page, """
        () => new Promise((resolve, reject) => {
            const req = indexedDB.open('svrnty', 2);
            req.onsuccess = () => {
                const db = req.result;
                const tx = db.transaction('settings', 'readonly');
                const getReq = tx.objectStore('settings').get('active_fingerprint');
                getReq.onsuccess = () => { db.close(); resolve(getReq.result?.value || null); };
                getReq.onerror = () => { db.close(); reject(getReq.error); };
            };
            req.onerror = () => reject(req.error);
        })
    """)

    collision_fp = "collision000000ff"

    # Insert first contact
    inject_idb_record(page, "contacts", {
        "id": "collision-contact-001",
        "fingerprint": collision_fp,
        "owner_fingerprint": fp,
        "name": "Contact Alpha",
        "email": "alpha@test.local",
        "public_key": "key-alpha",
        "trust_level": "known",
        "added_at": "2026-06-01T00:00:00Z",
    })

    # Insert second contact with SAME fingerprint but different id
    # The unique index on 'fingerprint' should prevent this or raise
    collision_error = None
    try:
        inject_idb_record(page, "contacts", {
            "id": "collision-contact-002",
            "fingerprint": collision_fp,
            "owner_fingerprint": fp,
            "name": "Contact Beta",
            "email": "beta@test.local",
            "public_key": "key-beta",
            "trust_level": "known",
            "added_at": "2026-06-02T00:00:00Z",
        })
    except Exception as e:
        collision_error = str(e)

    # Check what actually got stored
    contacts = get_idb_records(page, "contacts")
    same_fp = [c for c in contacts if c.get("fingerprint") == collision_fp]

    if collision_error:
        record("FM-6: Unique index enforced", True,
               f"IndexedDB rejected duplicate: {collision_error[:80]}")
    elif len(same_fp) == 1:
        # Second put may have overwritten via the unique index — check which survived
        survivor = same_fp[0]
        record("FM-6: Unique index enforced", True,
               f"Upsert: only one record with fp, survivor={survivor.get('name')}")
    elif len(same_fp) == 2:
        record("FM-6: Unique index enforced", False,
               "SECURITY: Two contacts with same fingerprint — unique constraint not enforced. "
               "keyPath is 'id', unique index is on 'fingerprint'. If the index silently allows "
               "duplicates, identity confusion is possible.")
    else:
        record("FM-6: Unique index enforced", False, f"Unexpected state: {len(same_fp)} records")

    # Reload and check contacts display
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(3000)
    contacts_tab = page.locator('button:has-text("CONTACTS")')
    if contacts_tab.count() > 0:
        contacts_tab.first.click()
        page.wait_for_timeout(1000)
    shot(page, "01_collision_contacts", "fm6")

    critical = [e for e in js_errors if "TypeError" in e or "ReferenceError" in e]
    record("FM-6: No crash on collision", len(critical) == 0,
           f"{len(critical)} JS errors" if critical else "Clean")

    ctx.close()


# ── Runner ──────────────────────────────────────────────────────

def run():
    print("\n" + "=" * 60)
    print("  SVRNTY Failure Model Simulations — Flint (Red Team)")
    print("=" * 60 + "\n", flush=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        test_key_loss(browser)
        test_corrupt_identity(browser)
        test_orphan_contacts(browser)
        test_network_partition(browser)
        test_relay_timeout(browser)
        test_identity_collision(browser)

        browser.close()

    # Summary
    print("\n" + "=" * 60)
    print("  FAILURE MODEL RESULTS")
    print("=" * 60)
    passed = sum(1 for _, p, _ in RESULTS if p)
    failed = sum(1 for _, p, _ in RESULTS if not p)
    for name, p, detail in RESULTS:
        status = "PASS" if p else "FAIL"
        line = f"  [{status}] {name}"
        if detail:
            line += f" -- {detail}"
        print(line)
    print(f"\n  Total: {passed} passed, {failed} failed")
    print(f"  Screenshots: {SHOTS}/")
    print("=" * 60)

    # Update DAG
    dag_path = Path("/home/alpha/svrnty/ui_test_dag.json")
    dag = {}
    if dag_path.exists():
        try:
            dag = json.loads(dag_path.read_text())
        except Exception:
            pass

    dag["failure_models"] = {
        "last_run": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "passed": passed,
        "failed": failed,
        "results": [{"name": n, "passed": p, "detail": d} for n, p, d in RESULTS],
        "screenshots": str(SHOTS),
    }
    dag_path.write_text(json.dumps(dag, indent=2))

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
