"""Reproduction for the _scrub_uri gaps reported in GHSA-xxv5-4xqw-4rmx.

Calls the real _scrub_uri from the installed jupyter_server with a canary
value and checks, per case, whether the canary survives in the output.
Exit code 0 means every reported leak is scrubbed and both controls behave.
Exit code 1 lists the cases that still leak.
"""

import sys

from jupyter_server.log import _scrub_uri

CANARY = "CANARYVALUE"

# (label, uri, expect_scrubbed)
CASES = [
    # anchor control: the shape the 2.21.0 fix already covered
    ("anchor ?token=", "http://example.com/tree?token=" + CANARY, True),
    # reported leaks: case variants of listed keys
    ("case ?Token=", "http://example.com/tree?Token=" + CANARY, True),
    ("case ?TOKEN=", "http://example.com/tree?TOKEN=" + CANARY, True),
    ("case ?Code=", "http://example.com/cb?Code=" + CANARY, True),
    ("case ?State=", "http://example.com/cb?State=" + CANARY, True),
    ("case ?_XSRF=", "http://example.com/tree?_XSRF=" + CANARY, True),
    # reported leak: semicolon separation hides the key in the previous part
    ("semicolon ;token=", "http://example.com/tree?a=1;token=" + CANARY, True),
    # reported leak: percent-encoded key
    ("encoded ?%74oken=", "http://example.com/tree?%74oken=" + CANARY, True),
    # reported leak: credential parameter outside the fixed list
    ("unlisted ?password=", "http://example.com/login?password=" + CANARY, True),
    # benign control: ordinary parameters must pass through byte-identical
    ("benign unchanged", "http://example.com/tree?normal=value&other=1", False),
]

failures = []
for label, uri, expect_scrubbed in CASES:
    out = _scrub_uri(uri)
    leaked = CANARY in out
    if expect_scrubbed and leaked:
        failures.append(label)
        print(f"LEAK  {label:24s} -> {out}")
    elif not expect_scrubbed and out != uri:
        failures.append(label)
        print(f"CHANGED (should be identical) {label} -> {out}")
    else:
        print(f"ok    {label:24s} -> {out}")

if failures:
    print(f"\n{len(failures)} case(s) failing: {', '.join(failures)}")
    sys.exit(1)
print("\nAll cases behave as expected.")
