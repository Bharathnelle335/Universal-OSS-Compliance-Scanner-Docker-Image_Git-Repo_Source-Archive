import sys
import json
import pandas as pd
from collections import defaultdict
import requests
import time

syft_file = sys.argv[1]
grype_file = sys.argv[2]
scanoss_file = sys.argv[3]

excel_out = "compliance_merged_report.xlsx"
json_out = "compliance_merged_report.json"
grype_excel = "grype_components_report.xlsx"
scanoss_excel = "scanoss_components_report.xlsx"

def parse_syft(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    components = []
    for item in data.get("packages", []):
        name = item.get("name")
        version = item.get("versionInfo") or item.get("version")
        license = item.get("licenseDeclared")
        components.append({
            "component": name,
            "version": version,
            "source": "syft",
            "license": license,
            "license_source": "syft" if license else "",
            "enriched_license": None,
            "license_url": "unknown"
        })
    return components

def parse_grype(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    licenses = defaultdict(str)
    grype_rows = []
    for match in data.get("matches", []):
        pkg = match.get("artifact", {})
        name = pkg.get("name")
        version = pkg.get("version")
        license_list = match.get("licenses", [])
        license = license_list[0].get("spdx") if license_list else pkg.get("license")
        if name and version:
            key = f"{name}@{version}"
            licenses[key] = license
            grype_rows.append({
                "component": name,
                "version": version,
                "source": "grype",
                "license": license,
                "license_source": "grype",
                "enriched_license": None,
                "license_url": "unknown"
            })
    return licenses, grype_rows

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
                        "license": license,
                        "license_source": "scanoss",
                        "enriched_license": None,
                        "license_url": "unknown"
                    })
        return matched
    except Exception:
        return []

def enrich_license(component):
    name = component["component"]
    version = component["version"] or ""
    headers = {"Accept": "application/json"}

    # Try GitHub
    try:
        time.sleep(0.2)
        url = f"https://api.github.com/repos/{name}/license"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            return data.get("license", {}).get("spdx_id"), url
    except: pass

    # Try NPM
    try:
        time.sleep(0.2)
        url = f"https://registry.npmjs.org/{name}"
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()
            license = data.get("license")
            return license, url
    except: pass

    # Try PyPI
    try:
        time.sleep(0.2)
        url = f"https://pypi.org/pypi/{name}/json"
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()
            license = data.get("info", {}).get("license")
            return license, url
    except: pass

    return None, "unknown"

syft_components = parse_syft(syft_file)
grype_licenses, grype_components = parse_grype(grype_file)
scanoss_components = parse_scanoss(scanoss_file)

for comp in syft_components:
    key = f"{comp['component']}@{comp['version']}"
    if not comp["license"] and key in grype_licenses:
        comp["license"] = grype_licenses[key]
        comp["license_source"] = "grype"

    enriched_license, license_url = enrich_license(comp)
    if enriched_license:
        comp["enriched_license"] = enriched_license
        comp["license_url"] = license_url

merged = syft_components + scanoss_components

# Create DataFrames
df_merged = pd.DataFrame(merged).drop_duplicates(subset=["component", "version", "license", "enriched_license"])
df_grype = pd.DataFrame(grype_components).drop_duplicates()
df_scanoss = pd.DataFrame(scanoss_components).drop_duplicates()

# Export to files
df_merged.to_excel(excel_out, index=False)
df_merged.to_json(json_out, orient="records", indent=2)
df_grype.to_excel(grype_excel, index=False)
df_scanoss.to_excel(scanoss_excel, index=False)

print(f"✅ Exported: {excel_out}, {json_out}, {grype_excel}, {scanoss_excel}")