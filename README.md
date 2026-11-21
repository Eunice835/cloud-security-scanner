# Cloud Security Scanner

A command-line tool that scans AWS accounts for common security misconfigurations and writes the findings to an HTML report.

## Features

- **AWS scanners:** S3, IAM, EC2 and CloudTrail checks, plus extended `ec2_advanced` and `cloudtrail_advanced` scans
- **Profiles:** `all` (S3, IAM, EC2, CloudTrail) and `all_aws` (all of the above including the advanced scans)
- **Integrations:** Trivy (filesystem or container image scans), Stratus Red Team and Pacu (parses their JSON results)
- **HTML reports** generated with Jinja2

## Installation

~~~bash
git clone https://github.com/Eunice835/cloud-security-scanner.git
cd cloud-security-scanner
pip install -r requirements.txt
~~~

The scanners use boto3, so configure your AWS credentials the usual way (environment variables or `~/.aws/credentials`). Only scan accounts you are authorized to assess. Trivy needs to be installed separately if you use that option.

## Usage

Run from the repository root:

~~~bash
# One scanner
python -m cloud_security_scanner.main --service s3

# Everything (S3, IAM, EC2, CloudTrail) with a custom report name
python -m cloud_security_scanner.main --service all --output report.html

# All AWS scanners including the advanced ones
python -m cloud_security_scanner.main --service all_aws

# Trivy scan of a folder or image
python -m cloud_security_scanner.main --service trivy --trivy-target . --trivy-mode fs

# Parse existing Stratus or Pacu results
python -m cloud_security_scanner.main --service stratus --stratus-results-json results.json
python -m cloud_security_scanner.main --service pacu --pacu-results-json export.json
~~~

### Options

| Option | Description |
|--------|-------------|
| `--service` | One of `s3`, `iam`, `ec2`, `ec2_advanced`, `cloudtrail`, `cloudtrail_advanced`, `all`, `all_aws`, `trivy`, `stratus`, `pacu` |
| `--output` | Report filename (default `security_report.html`) |
| `--trivy-target` | Path or image reference for Trivy (default `.`) |
| `--trivy-mode` | `fs` or `image` (default `fs`) |
| `--stratus-results-json` | Stratus JSON results file (optional) |
| `--pacu-results-json` | Pacu JSON export (optional) |

## Project structure

~~~
cloud-security-scanner/
├── cloud_security_scanner/   # main package: scanners, integrations, utils, rules, reports
├── tests/                    # pytest suite (uses moto to mock AWS)
├── rules/                    # scanning rules
├── reports/                  # generated reports
├── config.yaml
└── requirements.txt
~~~

## Running the tests

~~~bash
pytest
~~~

Tests mock AWS with [moto](https://github.com/getmoto/moto), so no real account is needed.
