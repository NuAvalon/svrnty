# svrnty — frontend build queue

Work top-down: the top **unchecked** item first. Each item is UI-to-a-spec ("render-glass") — the crypto / gate / PSI / trust plumbing lives behind stable hooks maintained by the core team; you wire the UI to those hooks, you do not implement or modify them. Open a PR per item into the canonical branch; check the item off in the PR.

**Note:** the render-glass items built ahead during the review hold (join-by-link, camera scan, honesty-copy, cloud-backup, notification area, mutual-contacts overlay) are already in draft PRs under review — do NOT rebuild them. This is the next batch.

**P0 — Distress: disabled state (life-safety) — verify shipped**
- [ ] Confirm the Distress control renders DISABLED + labelled "Coming": copy states plainly it isn't live, no present-tense reassurance, and the state never reads as "calling for help" (no alarm banner, no auto-dial, no "EMERGENCY" prominence). If already merged, check off; otherwise this ships first.

**P1 — core connect (build these next, top-down)**
- [ ] **Send / update a contact method**: the add-or-update flow for a contact method, plus a "shared with" surface showing who the update propagates to. Wire to the existing per-recipient-encrypt hook; render only what the hook reports.
- [ ] **Version history + one-tap revert**: a view of a contact method's prior revisions + a "restore previous" control. Revisions come from the existing signed-revision hook — render them, never compute them.
- [ ] **Deep-linked contact methods**: tap a contact method to open the right app (`wa.me/`, `tel:`, `signal.me/`, `mailto:` …). Pure frontend, no crypto.
- [ ] **Trust / untrust / remove / block controls + confirm dialogs**: the controls and their confirmations. Trust is a boolean — trusted or not; never add scores, tiers, or ranking. The trust / relay calls are core-team hooks; you render the controls + confirmations and call the hook.
- [ ] **Import / export polish + export-behind-unlock**: tidy the import/export UI and gate export behind the unlock prompt. Encryption is the existing hook; you build the UI.

**P2 — fast-follow (after P1 lands)**

**Note:** app-lock, biometric unlock, tag management, reach / disclosure settings, and the about page are already in draft PRs under review — do NOT rebuild them; listed here for tracking, not fresh build.

- [ ] **App-lock screen**: lock/unlock UX (the wrapping-key unwrap is a core-team hook; you build the screen).
- [ ] **Biometric unlock**: passkey / WebAuthn unlock UX over the existing hook.
- [ ] **Tag management**: create / edit / assign tags. Tags stay client-only and are stripped on the wire by the core team — never send them.
- [ ] **Reach / disclosure settings**: the private / first-degree / second-degree toggle chrome. Never compute who-can-see-what in the UI — render what the hook returns; fail closed.
- [ ] **About page**: render the provided copy.

