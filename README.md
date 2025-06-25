# 🔍 Web Vulnerability Scanner

A Python-based tool to scan web applications for common security issues, including:

- 🔐 Insecure HTTP headers
- 🚪 Open ports (via `nmap`)
- 🗂️ Directory traversal vulnerabilities
- 💉 Basic SQL injection testing (optional)

> ⚠️ **Ethical Use Only:** Only use this tool on systems you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.

---

## 📦 Features

- ✅ HTTP Security Header Analysis
- ✅ Port Scanning using Nmap
- ✅ Basic Directory Traversal Checks
- ✅ Optional SQL Injection Checks
- ✅ Output results to `scan_report.txt`
- ✅ Beginner-Friendly and Educational
- ✅ GitHub Actions Linting Workflow

---

## 🛠 Prerequisites

- Python 3
- `nmap` (`sudo apt install nmap`)
- Python packages:
  ```bash
  pip3 install -r requirements.txt
