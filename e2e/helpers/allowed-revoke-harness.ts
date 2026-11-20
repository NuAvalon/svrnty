// Browser-side harness for #959, bundled by esbuild and injected into a page as ONE bundle with the notes-store harness, so both see the SAME client store (a separate bundle has its
// own copy, and its own locked session). It adds nothing of its own: the app's real consent-change hook and the real know-layer tick step, called directly, with the build-time PSI gate
// forced OPEN (this bundle is not part of the Next build, so it cannot see the dev domain the gate reads). The spec proves the app's OWN gate is on through the real Remove path.
import './freeze-store-harness';
import { reconcileAllowedOnConsentChange, runAllowedRevokeTick } from '../../src/lib/sync/reconcile-allowed-hook';
import { resetRevokeState } from '../../src/lib/sync/allowed-revoke';

declare global {
  interface Window {
    __ar: {
      /** what going open does: the real hook with the consent of a peer who is allowed a row. Resolves with the hook's own answer. */
      add(owner: string, peer: string): Promise<unknown>;
      /** the know-layer tick's step 0: ask the satellite what it lists, send every DELETE that is owed */
      tick(owner: string): Promise<void>;
      /** let the retry windows pass (an in-memory schedule; the durable guarantee is that the satellite keeps listing a peer until its DELETE is confirmed) */
      reset(): void;
    };
  }
}

window.__ar = {
  add: (owner, peer) => reconcileAllowedOnConsentChange({ ownerFp: owner, senderFp: peer, consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false }, gate: () => true }),
  tick: (owner) => runAllowedRevokeTick(owner, { gate: () => true }),
  reset: () => resetRevokeState(),
};
