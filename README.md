# WebReconX

A compact Python tool for educational web pentesting & reconnaissance.

> ⚠ **Ethical Use Only** — This tool is intended for security research and authorized testing only.  
> The author is not responsible for any misuse.

---

## ✨ Features

- **Directory Enumeration** — Quickly discover hidden paths & resources.
- **Admin/Login Panel Finder** — Identify potential entry points.
- **Technology & CMS Fingerprinting** — Detect backend frameworks, libraries, and CMS.
- **JavaScript Scraper** — Extract JS files and look for endpoints or API keys.
- **Parameter Fuzzing** — Detect reflected parameters, LFI, and SQLi indicators.
- **Robots.txt Parser** — Identify disallowed paths and crawling hints.

---

## 📦 Installation

```bash
git clone https://github.com/YOURUSERNAME/webreconx.git
cd webreconx
pip install -r requirements.txt
```

# Usage

python webreconx.py --url https://target.tld --mode MODE

| Mode     | Description                     |
| -------- | ------------------------------- |
| `dir`    | Directory enumeration           |
| `admin`  | Find admin/login panels         |
| `tech`   | Technology & CMS fingerprinting |
| `js`     | JavaScript scraping             |
| `params` | Parameter fuzzing               |
| `all`    | Run all modules                 |


# Example

python webreconx.py --url https://example.com --mode all

[INFO] Scanning https://example.com

[+] Found directory: /admin/

[+] Technology: Apache, PHP 8.1

[+] JS file: /static/js/app.js

[!] Possible API key found in app.js



