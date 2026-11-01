## What and why

## Status strings
<!-- REQUIRED (Archie, lane:svrnty #3125). For EVERY new or changed status word this PR writes: a UI label or notice, a
     hop-trail row, a CLI or stderr line, a JSON status field. One line each:
       "<the string>" → <the event that makes it true> → written only AFTER that event succeeds? y / n + why
     Write "none" only if the PR adds or changes no status string.
     Why: on 2026-10-31 the same bug shipped four times, each caught only by a reviewer: "Caught up." on a failed poll,
     "POLL REFUSED: HTTP 200" for a relay that answered, "rc 0 = green" from print-only checks, and "dropped on this host"
     written before the commit. A status word is a claim; it is true only after the event that sets it. -->
Status strings:

## Tests
<!-- What you ran, with counts. For a fix, the NEG that goes RED without it (a mutant). -->

<!-- SENSITIVE PATHS: if CI's sensitive-paths step lists any file, add a line that STARTS with "Sensitive-paths:" saying what
     changed and who reviewed it. It is deliberately not pre-filled here: a pre-filled line would satisfy the check for every PR. -->
