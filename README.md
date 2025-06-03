# 🛰️ Origin IP Recon Tool

> A powerful multi-source OSINT tool to gather and verify real IP addresses of a domain from various public services and validate them using [httpx-toolkit](https://github.com/projectdiscovery/httpx).

---

## 📌 Features

- 🔍 Collects IPs from multiple OSINT sources:
  - VirusTotal
  - AlienVault OTX
  - URLScan.io
  - ViewDNS
  - DNSRecon
  - SPF Records
  - SecurityTrails
- ⚙️ Verifies each IP using `httpx-toolkit` across ports `80` and `443`
- 🧵 Multi-threaded verification engine
- 📄 Generates two clean output files:
  - `verified_ips.txt` — IPs that return HTTP 2xx or 3xx
  - `unverified_ips.txt` — All others (timeouts, 4xx, 5xx, etc.)
- 🔐 Secure API key handling via `.env` file

---

## 📦 Requirements

- Python 3.8+
- `httpx-toolkit` (CLI tool)
- External tools:
  - `curl`, `jq`, `dig`, `dnsrecon`
- Python packages:
  - `python-dotenv`

---

## 🛠️ Installation

1. **Clone the repo**:

```bash
git clone https://github.com/piyushaga27/Origin-IP-Recon.git
cd Origin-IP-Recon
```

2. **Install Python dependencies**:

```bash
pip install -r requirements.txt
```

3. **Install external tools** (if not already):

```bash
sudo apt install dnsrecon jq curl dnsutils
```

4. **Install `httpx-toolkit` (by ProjectDiscovery)**:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Ensure `$GOPATH/bin` is in your `$PATH`.

---

## 🔐 API Key Setup

1. **Create your config** file:

```bash
cp .env.example .env
```

2. **Edit `.env`** and fill in your API keys:

```env
VirusTotal_API_KEY=your_virustotal_key
SecurityTrails_API_KEY=your_securitytrails_key
VIEWDNS_API_KEY=your_viewdns_key
```

> 🚫 Never commit `.env` to Git. It’s ignored in `.gitignore`.

---

## 🚀 Usage

```bash
python3 main.py --domain example.com
```

Optional flags:
- `-t 20` → Use 20 threads instead of the default 10

---

## 📂 Output Files

After running, you'll get:

- `verified_ips.txt` — Valid IPs responding with HTTP 2xx/3xx
- `unverified_ips.txt` — IPs that didn't respond or failed

---

## 💡 Example Output

```
[✓] Total unique IPs found: 52
[✓] Starting validation threads...

[+] Done! Verified: 14, Unverified: 38
[✓] Results saved to 'verified_ips.txt' and 'unverified_ips.txt'
```

---

## 🤝 Contributing

Pull requests are welcome! You can also:
- Help Integrating additional OSINT sources
- Submit a GitHub issue for bugs
- Help add support for export to JSON/CSV

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙋‍♂️ Author

**Piyush Agarwal**  
Security Researcher & Automation Enthusiast
GitHub: [@piyushaga27](https://github.com/piyushaga27)
Portfolio website: https://piyushaga27.github.io/
---

## ☕ Support

If this tool helps you, consider giving it a ⭐ on GitHub and sharing it with others!

