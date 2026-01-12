<p align="center">
  <img src="logo.png" width="800">
</p>


---

# XssAi

An advanced automated Reflected XSS vulnerability scanner that combines traditional web crawling and payload injection with AI-powered validation using multiple LLM agents.
This tool is designed for educational purposes, security research, and authorized penetration testing only.

---

## Features

* Smart web crawler that scans internal pages within the same domain
* Automatically discovers and tests GET parameters
* Extracts and tests HTML forms (GET and POST)
* Uses multiple real-world XSS payloads
* Tests each parameter individually to reduce false positives
* Supports encoded and obfuscated payloads
* AI-powered validation using multiple agents (CrewAI + LLM)
* Classifies vulnerabilities by severity (Critical / High / Medium / Low)
* Determines exploitability and confidence level
* Generates detailed scan reports
* Displays vulnerable parameters
* Generates ready-to-use exploit URLs
* Built-in rate limiting with request delay and hourly quota

---

## Built With

* Python 3
* requests
* BeautifulSoup4
* urllib
* CrewAI
* LLM (Gemini or compatible models)

---

## Installation

```bash
git clone https://github.com/yourusername/XssAi.git
cd XssAi
pip install -r requirements.txt
```

Set your API key:

```bash
export GEMINI_API_KEY="your_api_key_here"
```

Run the tool:

```bash
python3 XssAi.py
```

---

## Example Usage

```
Target URL: https://example.com

[ XSS GET - HIGH ]
Vulnerable Parameter: search  
Payload: <img src=x onerror=alert(1)>  
Confidence: High  
```

Generated exploit URL example:

```
https://example.com/?search=<img src=x onerror=alert(1)>
```

---

## Output

The tool generates a report file such as:

```
xss_scan_results_20260112_183233.txt
```

The report includes:

* Vulnerability type
* Affected URL
* Vulnerable parameter
* Payload used
* Severity level
* Confidence level
* AI analysis
* Exploit URLs

---

## Legal Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Do not use this tool against any system without explicit written permission.
The developer is not responsible for any misuse of this software.

---

## Author

Developed by seny
Security Researcher | Python Developer | Offensive Security Enthusiast


* CONTRIBUTING.md
* Badges احترافية (بدون إيموجيز)
