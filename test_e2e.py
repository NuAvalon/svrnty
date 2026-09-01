#!/usr/bin/env python3
"""svrnty E2E QA — Flint Fork 39
Tests: identity creation, contact addition, trust map population, security fixes.
"""
import sys
import time
from playwright.sync_api import sync_playwright

BASE = "http://localhost:3333"
RESULTS = []

def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    RESULTS.append((name, passed, detail))
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""), flush=True)

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()

        # Track external requests
        external_font_requests = []
        def on_request(req):
            if "fonts.googleapis" in req.url or "fonts.gstatic" in req.url:
                external_font_requests.append(req.url)
        page.on("request", on_request)

        # Track JS errors
        js_errors = []
        page.on("pageerror", lambda err: js_errors.append(str(err)))

        # ── TEST 1: Page loads ──
        print("\n[1] Loading page...", flush=True)
        resp = page.goto(BASE, wait_until="networkidle")
        record("Page loads", resp.status == 200, f"HTTP {resp.status}")

        # ── TEST 2: No Google Fonts ──
        print("[2] Checking Google Fonts...", flush=True)
        time.sleep(1)
        record("No Google Fonts leaks", len(external_font_requests) == 0,
               f"{len(external_font_requests)} requests" if external_font_requests else "Clean")

        # ── TEST 3: Gate screen ──
        print("[3] Checking gate screen...", flush=True)
        forge_btn = page.locator("text=Start")
        record("Gate screen renders", forge_btn.is_visible(), "Start button visible")

        # ── TEST 4: Create identity ──
        print("[4] Creating identity...", flush=True)
        forge_btn.click()
        time.sleep(0.5)

        page.locator('input[placeholder="Your name"]').fill("QA Tester")
        page.locator('input[placeholder="your@email.com"]').fill("qa@test.local")

        # F1 fix: unlock passphrase encrypts keys at rest (optional)
        passphrase_input = page.locator('input[placeholder="Encrypts your keys at rest"]')
        if passphrase_input.is_visible():
            passphrase_input.fill("test-unlock-phrase-12chars")
            page.wait_for_timeout(300)  # confirm field appears
            confirm_input = page.locator('input[placeholder="Confirm passphrase"]')
            if confirm_input.is_visible():
                confirm_input.fill("test-unlock-phrase-12chars")

        page.locator('button:has-text("Start")').last.click()

        print("  Waiting for key generation...", flush=True)
        page.wait_for_timeout(8000)

        # Check dashboard is visible (any tab)
        tabs_visible = (
            page.locator('button:has-text("Galaxy")').first.is_visible() or
            page.locator('text=constellation').first.is_visible()
        )
        record("Identity created", tabs_visible, "Dashboard with tabs visible")

        # ── TEST 5: Trust map empty ──
        print("[5] Checking trust map empty state...", flush=True)
        empty_msg = page.locator('text=constellation is empty')
        trust_map_empty = empty_msg.count() > 0 and empty_msg.first.is_visible()
        record("Trust map empty state", trust_map_empty, "'constellation is empty' shown")

        # ── TEST 6: Navigate to Contacts ──
        print("[6] Opening Contacts tab...", flush=True)
        contacts_tab = page.locator('button:has-text("CONTACTS")')
        if contacts_tab.count() > 0:
            contacts_tab.first.click()
            page.wait_for_timeout(500)
        contacts_visible = page.locator('text=Add Contact').first.is_visible(timeout=3000)
        record("Contacts tab opens", contacts_visible)

        # ── TEST 7: Add a contact ──
        print("[7] Adding a contact...", flush=True)
        contact_added = False
        add_btn = page.locator('button:has-text("Add Contact")')
        if add_btn.count() > 0:
            add_btn.first.click()
            page.wait_for_timeout(500)

            # Screenshot for debugging
            page.screenshot(path="/tmp/svrnty_add_contact_dialog.png")

            # Fill contact form fields
            page.locator('input[placeholder="Contact name"]').fill("Alice Sovereignty")
            page.locator('input[placeholder="PGP fingerprint"]').fill("a1b2c3d4e5f6789012345678901234567890abcd")

            page.wait_for_timeout(300)
            page.screenshot(path="/tmp/svrnty_add_contact_filled.png")

            # Click "Add as Known" submit button
            submit_btn = page.locator('button:has-text("Add as Known")')
            submit_btn.click()
            page.wait_for_timeout(1500)

            page.screenshot(path="/tmp/svrnty_after_add_contact.png")

            alice_visible = page.locator('text=Alice Sovereignty').is_visible(timeout=3000)
            contact_added = alice_visible
            record("Contact added", contact_added,
                   "Alice Sovereignty in list" if alice_visible else "Not visible — check /tmp/svrnty_after_add_contact.png")
        else:
            record("Contact added", False, "Add Contact button not found")

        # ── TEST 8: Trust map now populated ──
        print("[8] Checking trust map with contact...", flush=True)
        trust_tab = page.locator('button:has-text("Galaxy")')
        trust_populated = False
        if trust_tab.count() > 0:
            trust_tab.first.click()
            page.wait_for_timeout(2000)  # let canvas render with contact

            page.screenshot(path="/tmp/svrnty_trust_map_with_contact.png")

            empty_gone = not page.locator('text=constellation is empty').is_visible()
            canvas_exists = page.locator('canvas').count() > 0

            trust_populated = empty_gone and canvas_exists and contact_added
            detail = f"Empty gone: {empty_gone}, Canvas: {canvas_exists}, Contact added: {contact_added}"
            record("Trust map populates", trust_populated, detail)
        else:
            record("Trust map populates", False, "Trust Map tab not found")

        # ── TEST 9: Identity tab ──
        print("[9] Checking Identity tab...", flush=True)
        id_tab = page.locator('button:has-text("IDENTITY")')
        if id_tab.count() > 0:
            id_tab.first.click()
            page.wait_for_timeout(500)

            fp_visible = page.locator('text=/[a-f0-9]{8,}/i').first.is_visible(timeout=3000)
            record("Fingerprint displayed", fp_visible)

            ed25519 = page.locator('text=ED25519').first.is_visible(timeout=2000)
            record("ED25519 tag visible", ed25519)

            backup_btn = page.locator('button:has-text("Backup"), button:has-text("Export"), button:has-text("Download")')
            record("Backup button visible", backup_btn.count() > 0 and backup_btn.first.is_visible())
        else:
            record("Fingerprint displayed", False, "Identity tab not found")
            record("ED25519 tag visible", False)
            record("Backup button visible", False)

        # ── TEST 10: Relay single-use ──
        print("[10] Testing relay endpoint...", flush=True)
        import subprocess, json
        try:
            # Create relay via curl
            r = subprocess.run(
                ["curl", "-s", "-X", "POST", f"{BASE}/api/relay",
                 "-H", "Content-Type: application/json",
                 "-d", '{"encrypted":"test-sovereignty-data"}'],
                capture_output=True, text=True, timeout=10
            )
            resp_data = json.loads(r.stdout)
            code = resp_data.get("code", "")

            # Read relay (path param, not query param)
            r2 = subprocess.run(
                ["curl", "-s", f"{BASE}/api/relay/{code}"],
                capture_output=True, text=True, timeout=10
            )
            read_data = json.loads(r2.stdout)
            got_payload = read_data.get("encrypted") == "test-sovereignty-data"

            # Second read should fail (single-use)
            r3 = subprocess.run(
                ["curl", "-s", f"{BASE}/api/relay/{code}"],
                capture_output=True, text=True, timeout=10
            )
            second_data = json.loads(r3.stdout)
            single_use = "error" in second_data or "gone" in str(second_data).lower()

            record("Relay create+read", got_payload, f"Code: {code}")
            record("Relay single-use", single_use, "Gone after first read")
        except Exception as e:
            record("Relay create+read", False, str(e))
            record("Relay single-use", False, "Skipped")

        # ── TEST 11: Satellite proxy validation ──
        print("[11] Testing satellite proxy validation...", flush=True)
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-X", "POST", f"{BASE}/api/satellite/slug/%2e%2e%2fetc%2fpasswd/claim",
                 "-H", "Content-Type: application/json",
                 "-d", '{"pubkey":"test"}'],
                capture_output=True, text=True, timeout=10
            )
            # Should get 400 (invalid slug) not 200
            record("Path traversal blocked", r.stdout.strip() == "400", f"HTTP {r.stdout.strip()}")
        except Exception as e:
            record("Path traversal blocked", False, str(e))

        # ── TEST 12: No critical JS errors ──
        print("[12] Checking JS errors...", flush=True)
        critical = [e for e in js_errors if "TypeError" in e or "ReferenceError" in e or "SyntaxError" in e]
        record("No critical JS errors", len(critical) == 0,
               f"{len(critical)} errors: {critical[:3]}" if critical else "Clean")

        browser.close()

    # ── Summary ──
    print("\n" + "=" * 60)
    print("  svrnty E2E QA — Flint Fork 39")
    print("=" * 60)
    passed = sum(1 for _, p, _ in RESULTS if p)
    failed = sum(1 for _, p, _ in RESULTS if not p)
    for name, p, detail in RESULTS:
        status = "PASS" if p else "FAIL"
        line = f"  [{status}] {name}"
        if detail:
            line += f" — {detail}"
        print(line)
    print(f"\n  Total: {passed} passed, {failed} failed")
    print("=" * 60)
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(run())
