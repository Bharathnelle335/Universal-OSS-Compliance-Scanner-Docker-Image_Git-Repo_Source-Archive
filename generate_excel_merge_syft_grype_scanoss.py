import sys
import json
import pandas as pd
from collections import defaultdict
import requests
import time
import os

# Determine scan source identifier (docker image or git URL or tar/zip upload)
image_name = os.getenv("IMAGE_NAME", "scan").replace(":", "_").replace("/", "_").replace("@", "_")

# File names
syft_file = "syft-sbom.spdx.json"
grype_file = "grype-scan.json"
scanoss_file = "scanoss-results.json"

# Output file names
excel_out = f"{image_name}_compliance_merged_report.xlsx"
json_out = f"{image_name}_compliance_merged_report.json"
grype_excel = f"{image_name}_grype_components_report.xlsx"
scanoss_excel = f"{image_name}_scanoss_components_report.xlsx"
syft_excel = f"{image_name}_syft_components_report.xlsx"

def parse_syft(filepath):
    if not os.path.exists(filepath):
        return []
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
    if not os.path.exists(filepath):
        return defaultdict(str), []
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
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        matched = []
        for entry_list in data.values():
            for match in entry_list:
                component = match.get("component")
                version = match.get("version") or match.get("latest")
                license_objs = match.get("licenses", [])
                license_names = [lic.get("name") for lic in license_objs if "name" in lic]
                license_combined = ", ".join(license_names) if license_names else None
                license_url = license_objs[0].get("url") if license_objs and "url" in license_objs[0] else "unknown"

                if component:
                    matched.append({
                        "component": component,
                        "version": version,
                        "source": "scanoss",
                        "license": license_combined,
                        "license_source": "scanoss",
                        "enriched_license": None,
                        "license_url": license_url
                    })
        return matched
    except Exception as e:
        print(f"[ERROR] Failed to parse SCANOSS JSON: {e}")
        return []

def enrich_license(component):
    name = component["component"]
    version = component["version"] or ""
    headers = {"Accept": "application/json"}

    try:
        time.sleep(0.2)
        url = f"https://api.github.com/repos/{name}/license"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            return data.get("license", {}).get("spdx_id"), url
    except: pass

    try:
        time.sleep(0.2)
        url = f"https://registry.npmjs.org/{name}"
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()
            license = data.get("license")
            return license, url
    except: pass

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

# Parse all inputs
syft_components = parse_syft(syft_file)
grype_licenses, grype_components = parse_grype(grype_file)
scanoss_components = parse_scanoss(scanoss_file)

# Enrich syft components using Grype and external data
for comp in syft_components:
    key = f"{comp['component']}@{comp['version']}"
    if not comp["license"] and key in grype_licenses:
        comp["license"] = grype_licenses[key]
        comp["license_source"] = "grype"
    enriched_license, license_url = enrich_license(comp)
    if enriched_license:
        comp["enriched_license"] = enriched_license
        comp["license_url"] = license_url

# Combine syft and scanoss for merged report
merged = syft_components + scanoss_components
df_merged = pd.DataFrame(merged).drop_duplicates(subset=["component", "version", "license", "enriched_license"])
df_merged.to_excel(excel_out, index=False)
df_merged.to_json(json_out, orient="records", indent=2)

# Grype
df_grype = pd.DataFrame(grype_components).drop_duplicates()
df_grype.to_excel(grype_excel, index=False)

# Scanoss
df_scanoss = pd.DataFrame(scanoss_components).drop_duplicates()
df_scanoss.to_excel(scanoss_excel, index=False)

# Syft
df_syft = pd.DataFrame(syft_components)
if not df_syft.empty:
    df_syft = df_syft[["component", "version", "license", "license_source", "license_url"]].drop_duplicates()
else:
    df_syft = pd.DataFrame(columns=["component", "version", "license", "license_source", "license_url"])
df_syft.to_excel(syft_excel, index=False)

print(f"✅ Reports generated for: {image_name}")
