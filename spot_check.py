import json
import pathlib

data = json.loads(pathlib.Path("phase1_verify.json").read_text(encoding="utf-8"))
print("crucible_version in scan output:", data.get("crucible_version"))
print("grade:", data.get("grade"))
print("total_findings:", data.get("total_findings"))
print()

# Spot-check first 10 findings across all modules
count = 0
for module in data.get("modules", []):
    for finding in module.get("findings", []):
        if count >= 10:
            break
        atl = finding.get("atlas_technique", "MISSING")
        tac = finding.get("atlas_tactic", "MISSING")
        nf = finding.get("nist_function", "MISSING")
        nc = finding.get("nist_category", "MISSING")
        name = finding.get("attack_name", "?")
        print(f"Finding {count+1}: {name}")
        print(f"  atlas_technique : {atl}")
        print(f"  atlas_tactic    : {tac}")
        print(f"  nist_function   : {nf}")
        print(f"  nist_category   : {nc}")
        count += 1
    if count >= 10:
        break

print()
print(f"Spot-checked {count} findings.")

# Check ALL findings for empty atlas_technique
all_findings = [f for m in data.get("modules", []) for f in m.get("findings", [])]
empty_atlas = [f["attack_name"] for f in all_findings if not f.get("atlas_technique")]
empty_nist = [f["attack_name"] for f in all_findings if not f.get("nist_function")]
print(f"Total findings in scan: {len(all_findings)}")
print(f"Findings with EMPTY atlas_technique: {len(empty_atlas)}")
print(f"Findings with EMPTY nist_function  : {len(empty_nist)}")
if empty_atlas:
    print("  Empty ATLAS examples:", empty_atlas[:5])
if empty_nist:
    print("  Empty NIST examples:", empty_nist[:5])
