#!/usr/bin/env python3
"""svrnty Key Exchange E2E — Two-User Flow
Tests the complete identity exchange between Alice and Bob.

Flow:
  1. Alice creates identity
  2. Alice generates relay short code (encrypted dead-drop)
  3. Bob creates identity
  4. Bob opens relay link → decrypts → imports Alice as contact
  5. Verify Bob's contact list contains Alice

Screenshots saved to /tmp/svrnty_exchange/ for visual review.

Requires: playwright, dev server on localhost:3333
Author: Flint | 2026-06-19
"""
import json
import os
import re
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = "http://localhost:3333"
SHOTS = Path("/tmp/svrnty_exchange")
RESULTS = []


def shot(page, name, context_name=""):
    """Take a screenshot with a descriptive name."""
    SHOTS.mkdir(parents=True, exist_ok=True)
    prefix = f"{context_name}_" if context_name else ""
    path = SHOTS / f"{prefix}{name}.png"
    page.screenshot(path=str(path))
    return str(path)


def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    RESULTS.append((name, passed, detail))
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail else ""), flush=True)


def create_identity(page, name, email, context_name):
    """Create an identity on the gate screen. Returns True if dashboard appears."""
    resp = page.goto(BASE, wait_until="networkidle")
    if resp.status != 200:
        return False

    shot(page, "01_gate", context_name)

    # Click "Begin anew"
    forge_btn = page.locator("text=Begin anew")
    if not forge_btn.is_visible(timeout=5000):
        return False
    forge_btn.click()
    page.wait_for_timeout(500)

    # Fill identity form
    page.locator('input[placeholder="Your name"]').fill(name)
    page.locator('input[placeholder="your@email.com"]').fill(email)

    # Optional passphrase
    pp = page.locator('input[placeholder="Encrypts your keys at rest"]')
    if pp.is_visible():
        pp.fill("test-passphrase-12c")
        page.wait_for_timeout(300)
        confirm = page.locator('input[placeholder="Confirm passphrase"]')
        if confirm.is_visible():
            confirm.fill("test-passphrase-12c")

    shot(page, "02_form_filled", context_name)

    page.locator('button:has-text("BEGIN ANEW")').click()
    print(f"    Waiting for {name}'s key generation...", flush=True)
    page.wait_for_timeout(8000)

    shot(page, "03_dashboard", context_name)

    # Verify dashboard loaded
    tabs_visible = (
        page.locator('button:has-text("TRUST MAP")').first.is_visible() or
        page.locator('text=constellation').first.is_visible()
    )
    return tabs_visible


def get_share_link(page, context_name):
    """Navigate to Identity tab, click Share, generate relay short code.
    Returns (code, key_fragment) or (None, None) on failure.
    """
    # Go to Identity tab
    id_tab = page.locator('button:has-text("IDENTITY")')
    if id_tab.count() == 0:
        return None, None
    id_tab.first.click()
    page.wait_for_timeout(1000)
    shot(page, "04_identity_tab", context_name)

    # Look for a Share button
    share_btn = page.locator('button:has-text("Share"), button:has-text("share")')
    if share_btn.count() == 0:
        # Try looking for the share icon button
        share_btn = page.locator('[aria-label*="share" i], [title*="share" i]')
    if share_btn.count() == 0:
        # Fallback: try Contacts tab where share might live
        contacts_tab = page.locator('button:has-text("CONTACTS")')
        if contacts_tab.count() > 0:
            contacts_tab.first.click()
            page.wait_for_timeout(500)
            share_btn = page.locator('button:has-text("Share"), button:has-text("share")')

    if share_btn.count() == 0:
        shot(page, "04b_no_share_btn", context_name)
        return None, None

    share_btn.first.click()
    page.wait_for_timeout(1000)
    shot(page, "05_share_dialog", context_name)

    # Click the "Short Code" / "Link" tab in the share dialog
    link_tab = page.locator('text=Short Code')
    if link_tab.count() == 0:
        link_tab = page.locator('text=Link')
    if link_tab.count() > 0:
        link_tab.first.click()
        page.wait_for_timeout(500)

    # Click "Generate Link"
    gen_btn = page.locator('button:has-text("Generate Link")')
    if gen_btn.count() == 0:
        shot(page, "05b_no_generate_btn", context_name)
        return None, None

    gen_btn.first.click()
    page.wait_for_timeout(3000)
    shot(page, "06_short_code_generated", context_name)

    # Extract the short code link from the page
    # It should appear as text like "svrnty.is/c/XXXXXX#key..."
    code_el = page.locator("code")
    if code_el.count() == 0:
        shot(page, "06b_no_code_element", context_name)
        return None, None

    link_text = code_el.first.inner_text()
    # Parse: svrnty.is/c/{code}#{key}
    match = re.search(r'/c/([A-Za-z0-9]+)#(.+)', link_text)
    if not match:
        return None, None

    return match.group(1), match.group(2)


def import_via_relay(page, code, key_fragment, context_name):
    """Navigate Bob to the relay landing page and import the contact.
    Returns True if import succeeds.
    """
    url = f"{BASE}/c/{code}#{key_fragment}"
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(3000)
    shot(page, "07_relay_landing", context_name)

    # Check for "Package decrypted" status
    decrypted = page.locator('text=Package decrypted')
    if not decrypted.is_visible(timeout=5000):
        # Check for error
        err = page.locator('text=Link unavailable')
        if err.is_visible():
            shot(page, "07b_relay_error", context_name)
            return False
        shot(page, "07b_relay_unexpected", context_name)
        return False

    shot(page, "08_decrypted", context_name)

    # Click "IMPORT CONTACT"
    import_btn = page.locator('button:has-text("IMPORT CONTACT")')
    if import_btn.count() == 0:
        return False

    import_btn.first.click()
    page.wait_for_timeout(2000)
    shot(page, "09_imported", context_name)

    # Check for success
    imported = page.locator('text=Contact imported')
    already = page.locator('text=Already known')
    return imported.is_visible(timeout=3000) or already.is_visible(timeout=1000)


def verify_contact_in_list(page, contact_name, context_name):
    """Go to main page, check contacts tab for the imported contact.
    Returns (found_by_name, found_at_all) — allows detecting name display bug.
    """
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(2000)

    contacts_tab = page.locator('button:has-text("CONTACTS")')
    if contacts_tab.count() > 0:
        contacts_tab.first.click()
        page.wait_for_timeout(1000)

    shot(page, "10_contacts_list", context_name)

    # Check if any contact card is present (has Trust/Edit/Remove buttons)
    contact_cards = page.locator('button:has-text("Trust"), button:has-text("Edit")')
    has_contacts = contact_cards.count() > 0

    # Also check the tab label doesn't say (0)
    if not has_contacts:
        zero_tab = page.locator('text=CONTACTS (0)')
        has_contacts = zero_tab.count() == 0  # if (0) tab is absent, contacts exist

    # Look for the contact name specifically
    found_name = page.locator(f'text={contact_name}')
    name_visible = found_name.count() > 0 and found_name.first.is_visible(timeout=2000)

    return name_visible, has_contacts


def run():
    print("\n=== SVRNTY Key Exchange E2E ===\n", flush=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Two separate browser contexts = two separate IndexedDB stores
        alice_ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        bob_ctx = browser.new_context(viewport={"width": 1280, "height": 900})

        alice = alice_ctx.new_page()
        bob = bob_ctx.new_page()

        # Track JS errors
        alice_errors = []
        bob_errors = []
        alice.on("pageerror", lambda err: alice_errors.append(str(err)))
        bob.on("pageerror", lambda err: bob_errors.append(str(err)))

        # === STEP 1: Alice creates identity ===
        print("[1] Alice creates identity...", flush=True)
        alice_ok = create_identity(alice, "Alice Sovereign", "alice@test.local", "alice")
        record("Alice identity created", alice_ok)

        # === STEP 2: Bob creates identity ===
        print("[2] Bob creates identity...", flush=True)
        bob_ok = create_identity(bob, "Bob Trustworthy", "bob@test.local", "bob")
        record("Bob identity created", bob_ok)

        # === STEP 3: Alice generates relay short code ===
        print("[3] Alice generates share link...", flush=True)
        code, key_frag = None, None
        if alice_ok:
            code, key_frag = get_share_link(alice, "alice")
        record("Alice share link generated",
               code is not None and key_frag is not None,
               f"code={code}" if code else "Failed to extract code")

        # === STEP 4: Bob opens relay link and imports ===
        print("[4] Bob imports via relay...", flush=True)
        import_ok = False
        if code and key_frag and bob_ok:
            import_ok = import_via_relay(bob, code, key_frag, "bob")
        record("Bob imports Alice via relay", import_ok)

        # === STEP 5: Verify Alice appears in Bob's contacts ===
        print("[5] Verifying contact in Bob's list...", flush=True)
        name_found = False
        contact_exists = False
        if import_ok:
            name_found, contact_exists = verify_contact_in_list(bob, "Alice", "bob")
        record("Contact exists in Bob's list", contact_exists,
               "CONTACTS count > 0" if contact_exists else "No contacts found")
        record("Alice name displayed", name_found,
               "Name visible" if name_found else "BUG: contact imported but name not shown (peer_name vs name field mismatch)")

        # === STEP 6: Relay single-use (second visit should fail) ===
        print("[6] Verifying relay single-use...", flush=True)
        if code and key_frag:
            page3 = bob_ctx.new_page()
            page3.goto(f"{BASE}/c/{code}#{key_frag}", wait_until="networkidle")
            page3.wait_for_timeout(4000)
            shot(page3, "11_relay_second_visit", "bob")
            # The page should show an error state — no "IMPORT CONTACT" button
            import_btn_gone = page3.locator('button:has-text("IMPORT CONTACT")').count() == 0
            # Check for any error indicator
            error_shown = (
                page3.locator('text=Link unavailable').is_visible(timeout=2000) or
                page3.locator('text=expired').is_visible(timeout=500) or
                page3.locator('text=already been used').is_visible(timeout=500) or
                page3.locator('text=not found').is_visible(timeout=500)
            )
            record("Relay single-use enforced", import_btn_gone or error_shown,
                   f"import_btn_gone={import_btn_gone}, error_shown={error_shown}")
            page3.close()
        else:
            record("Relay single-use enforced", False, "Skipped — no code")

        # === STEP 7: No critical JS errors ===
        print("[7] Checking JS errors...", flush=True)
        critical_alice = [e for e in alice_errors if "TypeError" in e or "ReferenceError" in e]
        critical_bob = [e for e in bob_errors if "TypeError" in e or "ReferenceError" in e]
        record("No critical JS errors (Alice)", len(critical_alice) == 0,
               f"{len(critical_alice)} errors" if critical_alice else "Clean")
        record("No critical JS errors (Bob)", len(critical_bob) == 0,
               f"{len(critical_bob)} errors" if critical_bob else "Clean")

        alice_ctx.close()
        bob_ctx.close()
        browser.close()

    # === Summary ===
    print("\n" + "=" * 60)
    print("  SVRNTY Key Exchange E2E — Flint")
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

    # Write result to DAG file
    dag_path = Path(__file__).parent / "ui_test_dag.json"
    dag = {}
    if dag_path.exists():
        try:
            dag = json.loads(dag_path.read_text())
        except Exception:
            pass

    dag["key_exchange"] = {
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
