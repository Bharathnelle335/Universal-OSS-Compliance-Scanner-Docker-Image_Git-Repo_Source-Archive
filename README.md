# Universal OSS Compliance Scanner (Docker Image • Git Repo • Source Archive) using (Syft + Grype + SCANOSS)

This project performs OSS compliance scanning for:
- Docker images
- Git repositories
- Uploaded source archives (.zip or .tar.gz)

## Tools Used
- Syft → SBOM generation (SPDX/JSON)
- Grype → Vulnerability scan
- SCANOSS → Source code matching (optional fallback)
- Python → License enrichment + Excel report generation

## Supported Inputs
- `docker_image`: e.g., `nginx:latest`
- `git_url`: e.g., `https://github.com/example/repo.git`
- `upload-zip` or `upload-tar`: Upload your `.zip` or `.tar.gz` codebase

## Output
- Enriched SBOM (`syft-sbom.json`)
- License report (`license_report.xlsx`)
- SCANOSS results (`scanoss.spdx.json`, optional)

## How to Use
Trigger the GitHub Actions workflow:
- Select input type: `scan_type = docker | git | upload-zip | upload-tar`
- Provide the matching input value or upload

Results are uploaded as downloadable workflow artifacts.

## License
This project is licensed under the Apache License 2.0.  
See the [LICENSE](./LICENSE) file for details.
