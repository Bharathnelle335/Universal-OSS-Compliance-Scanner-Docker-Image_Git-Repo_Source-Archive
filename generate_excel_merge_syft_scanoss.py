"""
generate_excel_merge_syft_scanoss.py
Version: 1.1.0
Universal merger of Syft SBOM and SCANOSS results to Excel
Supports: Java (Maven, Gradle), NodeJS, Python, Go, C, etc.
"""

import pandas as pd
import json
import sys
import os

def load_syft_sbom(syft_file):
    with open(syft_file, 'r', encoding='utf-8') as f:
        syft_data = json.load(f)

    components = []
    for package in syft_data.get("packages", []):
        name = package.get("name", "Unknown")
        version = package.get("version", "Unknown")
        license_info = "Unknown"
        homepage = "N/A"

        if "licenseConcluded" in package:
            license_info = package["licenseConcluded"]
        elif "foundLicenses" in package and package["foundLicenses"]:
            license_info = package["foundLicenses"][0]

        if "homepage" in package and package["homepage"]:
            homepage = package["homepage"]

        components.append({
            "Name": name,
            "Version": version,
            "License": license_info,
            "License URL": homepage
        })

    return components

def load_scanoss_results(scanoss_file):
    with open(scanoss_file, 'r', encoding='utf-8') as f:
        scanoss_data = json.load(f)

    components = []

    for file_path, matches in scanoss_data.items():
        for match in matches:
            name = match.get("component", "Unknown")
            version = match.get("version", "Unknown")

            # License Handling
            license_info = "Unknown"
            license_url = "N/A"
            licenses = match.get("licenses", [])
            if licenses and isinstance(licenses, list):
                license_info = licenses[0].get("name", "Unknown")
                license_url = licenses[0].get("url", "N/A")

            components.append({
                "Name": name,
                "Version": version,
                "License": license_info,
                "License URL": license_url
            })

    return components

def main(syft_sbom_path, scanoss_result_path):
    syft_components = load_syft_sbom(syft_sbom_path)
    scanoss_components = load_scanoss_results(scanoss_result_path)

    syft_df = pd.DataFrame(syft_components)
    scanoss_df = pd.DataFrame(scanoss_components)

    syft_df.to_excel("syft-compliance-report.xlsx", index=False)
    scanoss_df.to_excel("scanoss-compliance-report.xlsx", index=False)

    merged_df = pd.concat([syft_df, scanoss_df], ignore_index=True).drop_duplicates()
    merged_df.to_excel("compliance-report.xlsx", index=False)

    print("✅ Excel reports generated successfully:")
    print("- compliance-report.xlsx")
    print("- syft-compliance-report.xlsx")
    print("- scanoss-compliance-report.xlsx")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_excel_merge_syft_scanoss.py syft-sbom.spdx.json scanoss-results.json")
        sys.exit(1)

    syft_sbom_path = sys.argv[1]
    scanoss_result_path = sys.argv[2]

    if not os.path.exists(syft_sbom_path):
        print(f"Error: {syft_sbom_path} not found.")
        sys.exit(1)
    if not os.path.exists(scanoss_result_path):
        print(f"Error: {scanoss_result_path} not found.")
        sys.exit(1)

    main(syft_sbom_path, scanoss_result_path)
