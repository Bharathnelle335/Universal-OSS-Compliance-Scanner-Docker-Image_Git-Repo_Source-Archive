import sys
import json
import pandas as pd
from collections import defaultdict
import requests
import time
import re
import os

# Determine scan source identifier (docker image or git URL)
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

syft_components = []
grype_components = []
scanoss_components = []

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
        components = {}
        for file_path, entries in data.items():
            for match in entries:
                component = match.get("component")
                version = match.get("version") or match.get("latest")
                license_entry = match.get("licenses", [{}])[0]
                license_name = license_entry.get("name")
                license_url = license_entry.get("url", "unknown")

                if component:
                    key = f"{component}@{version or 'unknown'}"
                    if key not in components:
                        components[key] = {
                            "component": component,
                            "version": version,
                            "source": "scanoss",
                            "license": license_name,
                            "license_source": "scanoss",
                            "enriched_license": None,
                            "license_url": license_url or "unknown"
                        }
        return list(components.values())
    except Exception as e:
        print(f"Error parsing SCANOSS: {e}")
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

if merged:
    df_merged = pd.DataFrame(merged).drop_duplicates(subset=["component", "version", "license", "enriched_license"])
    df_merged.to_excel(excel_out, index=False)
    df_merged.to_json(json_out, orient="records", indent=2)

if grype_components:
    df_grype = pd.DataFrame(grype_components).drop_duplicates()
    df_grype.to_excel(grype_excel, index=False)

if scanoss_components:
    df_scanoss = pd.DataFrame(scanoss_components).drop_duplicates()
    df_scanoss.to_excel(scanoss_excel, index=False)

if syft_components:
    df_syft = pd.DataFrame(syft_components)[["component", "version", "license", "license_source", "license_url"]].drop_duplicates()
    df_syft.to_excel(syft_excel, index=False)

print(f"✅ Reports generated for: {image_name}")
