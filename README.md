# Jupyter Server log scrubbing bypasses: researcher advisory and fix

Discovered, verified, and fixed by Gavin Blacklock (Epsilon0xCell).

## Summary

Jupyter Server scrubs secrets out of request URIs before they are written to
the server log. The scrubbing function, `_scrub_uri` in
`jupyter_server/log.py`, matches secret keys case-sensitively and splits the
query string only on `&`. Several ordinary shapes therefore pass through into
the log unchanged, carrying a live session token or credential with them:

- Case variants of listed keys: `?Token=`, `?TOKEN=`, `?Code=`, `?State=`,
  `?_XSRF=`
- A semicolon-separated parameter: `?a=1;token=`
- A percent-encoded key: `?%74oken=`
- A credential parameter outside the default list: `?password=`

The anchor shape, `?token=`, is scrubbed correctly. The variants above were
not, in the current release and in the code on the main branch at the time of
testing.

## Classification

- CWE-532: Insertion of Sensitive Information into Log File
- Researcher assessment: CVSS 2.6, Low (estimate). Reaching the leaked value
  requires access to the server log, so this is a hardening gap in a security
  control, scored as such. It is published here at that weight, no higher.

## Affected code

- Product: Jupyter Server (jupyter-server/jupyter_server)
- Tested and confirmed: release 2.21.1, and upstream main at commit
  e39ebd56b (2.22.0.dev0) on 2026-11-12
- Location: `jupyter_server/log.py`, function `_scrub_uri`

## Verification

The reproduction script in this repository, `repro_scrub_uri.py`, calls the
real `_scrub_uri` with a canary value across ten cases. Against the unpatched
code, 8 of the 10 cases leak the canary into the output. Against the patched
code, all 10 behave: every reported shape is scrubbed and both control cases
pass through untouched.

The fix was also verified with the project test suite: the new tests fail
before the patch (9 failed, 4 passed) and `tests/test_log.py` passes in full
after it (13 passed), with `tests/test_serverapp.py` passing 102 of 102 and
the project lint hooks clean.

## The fix

`fix.patch` in this repository is the complete change, against upstream main
e39ebd56b, commit 7bef4f669, three files, 61 insertions and 11 deletions:

- Keys are percent-decoded and lowercased before matching, and configured
  extra keys are lowercased as well, so case and encoding variants match.
- The query string is split on semicolons as well as ampersands, keeping the
  original separators.
- `password` is added to the default scrub list, and the server help text is
  updated to match.
- Tests cover all eight reported shapes plus the controls.

## Disclosure record

- 2026-11-12: reported privately through GitHub Security Advisories as
  GHSA-xxv5-4xqw-4rmx.
- 2026-11-12: the maintainers declined the report as not a vulnerability and
  closed the advisory. In the same ruling, an ordinary pull request improving
  the log scrubbing was welcomed.
- 2026-11-12: the jupyter-server organization blocked this account, which
  also prevents forking the repository to open that pull request.
- 2026-11-17: the finished patch was delivered to Jupyter Security directly,
  for the maintainers to use with credit or without, at their choice.
- 2026-11-17: this advisory is published by the researcher, for the record,
  because the private channel closed without a public one. No CVE has been
  requested. The maintainers' ruling stands on their tracker; the finding,
  the evidence, and the fix stand here, under the name of the person who did
  the work.

## Credit

Research, reproduction, fix, and tests: Gavin Blacklock (Epsilon0xCell).
