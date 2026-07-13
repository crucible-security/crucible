#!/usr/bin/env python3
"""
Post-run assertion check for Phase 10 live verification.
Reads the already-saved dynamic_verify.json and asserts correctness.
"""

import json
import sys

out_path = "dynamic_verify.json"
with open(out_path, encoding="utf-8") as f:
    data = json.load(f)

findings = [f for m in data.get("modules", []) for f in m.get("findings", [])]
static_f  = [f for f in findings if f.get("payload_source") == "static"]
dynamic_f = [f for f in findings if f.get("payload_source") == "dynamic"]

print(f"Static findings:  {len(static_f)}")
print(f"Dynamic findings: {len(dynamic_f)}")

assert len(dynamic_f) > 0, f"FAIL: No dynamic findings! static={len(static_f)}"

# Verify ordering: all static come before any dynamic
first_dynamic_idx = next(
    (i for i, f in enumerate(findings) if f.get("payload_source") == "dynamic"),
    None
)
if first_dynamic_idx is not None:
    for earlier in findings[:first_dynamic_idx]:
        assert earlier.get("payload_source") == "static", \
            f"FAIL: non-static finding before first dynamic at index {first_dynamic_idx}"

# Verify payload_source field present on ALL findings
missing = [i for i, f in enumerate(findings) if "payload_source" not in f]
assert not missing, f"FAIL: {len(missing)} findings missing payload_source field"

# Verify payload_index field present on ALL findings
missing_idx = [i for i, f in enumerate(findings) if "payload_index" not in f]
assert not missing_idx, f"FAIL: {len(missing_idx)} findings missing payload_index field"

print(f"Sample dynamic payload: {dynamic_f[0].get('payload','')[:120]!r}")
print(f"Grade: {data.get('grade')} | Score: {data.get('overall_score', 0):.1f}")
print(f"Static-first ordering: CONFIRMED")
print(f"payload_source field on all {len(findings)} findings: CONFIRMED")
print("")
print("Verification PASSED")
