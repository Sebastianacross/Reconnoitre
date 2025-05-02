# Reconnoitre

Reconnoitre is a modular website reconnaissance tool built in Python. It performs automated scanning of public-facing web targets to gather intelligence about domain configuration, content structure, and basic security posture.

This tool is ideal for penetration testers, bug bounty hunters, or developers conducting surface-level audits.

---

## 🚀 Features

- Subdomain enumeration (async)
- Directory brute-forcing (async)
- `robots.txt` detection
- Homepage link scraping
- WHOIS lookup
- IP resolution
- SSL certificate parsing
- Security header inspection
- CMS detection (WordPress, Joomla, Drupal)
- Page title extraction
- Broken link detection
- Directory indexing discovery
- JSON and CSV export support

---

## 🖥️ GUI Preview

Reconnoitre includes a simple `Tkinter` GUI that allows you to toggle features, select export formats, and supply custom wordlists.

---

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/reconnoitre.git
cd reconnoitre
pip install -r requirements.txt
python main.py
```
Requires Python 3.8+

## 📦 Dependencies
Listed in requirements.txt:
aiohttp
requests
beautifulsoup4
python-whois
PySimpleGUI (used in alternative GUI mode)

## 📂 Usage

You can run Reconnoitre either through the GUI or by importing the ReconScanner class in your own scripts.
```
from scanner import ReconScanner

scanner = ReconScanner("https://example.com", print)
scanner.run({
    "robots": True,
    "scrape": True,
    "whois": True,
    ...
})
scanner.export_results("json")
```
## 🛡️ Disclaimer

Reconnoitre is intended for educational and ethical use only. Always get proper authorization before scanning domains you do not own.

## 📄 License
MIT License
