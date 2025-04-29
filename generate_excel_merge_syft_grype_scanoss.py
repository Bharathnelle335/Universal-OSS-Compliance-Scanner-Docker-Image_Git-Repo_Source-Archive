import sys
import json
import pandas as pd
from collections import defaultdict

# Input files from CLI
syft_file = sys.argv[1]
grype_file = sys.argv[2]
scanoss_file = sys.argv[3]

# Output file names
excel_out = "compliance_merged_report.xlsx"
json_out = "compliance_merged_report.json"

def parse_syft(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    components = []
    for item in data.get("packages", []):
        name = item.get("name")
        version = item.get("versionInfo") or item.get("version")
        components.append({
            "component": name,
            "version": version,
            "source": "syft",
            "license": None
        })
    return components

def parse_grype(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    licenses = defaultdict(str)
    for match in data.get("matches", []):
        pkg = match.get("artifact", {})
        name = pkg.get("name")
        version = pkg.get("version")
        license = pkg.get("license") or match.get("vulnerability", {}).get("license")
        if name and version:
            key = f"{name}@{version}"
            licenses[key] = license
    return licenses

def parse_scanoss(filepath):
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        matched = []
        for entry in data:
            for match in entry.get("matches", []):
                component = match.get("component")
                license = match.get("licenses", [{}])[0].get("name")
                if component:
                    matched.append({
                        "component": component,
                        "version": None,
                        "source": "scanoss",
                        "license": license
                    })
        return matched
    except Exception:
        return []

# Parse inputs
syft_components = parse_syft(syft_file)
grype_licenses = parse_grype(grype_file)
scanoss_components = parse_scanoss(scanoss_file)

# Enrich syft with Grype license info
for comp in syft_components:
    key = f"{comp['component']}@{comp['version']}"
    comp["license"] = grype_licenses.get(key)

# Combine all
merged = syft_components + scanoss_components

# Output to Excel + JSON
df = pd.DataFrame(merged)
df.drop_duplicates(subset=["component", "version", "license"], inplace=True)
df.to_excel(excel_out, index=False)
df.to_json(json_out, orient="records", indent=2)

print(f"✅ Exported: {excel_out}, {json_out}, total components: {len(df)}")
