# LFI570rm - Advanced LFI Vulnerability Scanner

![LFI Scanner Banner](https://i.imgur.com/JKvQ8aP.png)

An advanced Local File Inclusion (LFI) vulnerability scanner with multi-threading, automatic payload generation, and comprehensive detection capabilities.

> ⚠️ **Legal Disclaimer**: This tool is for authorized security testing and educational purposes only. Unauthorized use against systems you don't own is illegal.

---

## 🚀 Features

- 🔁 Multi-threaded scanning for fast detection  
- 🧠 Automatic payload generation  
- 🔍 Comprehensive LFI pattern detection  
- 🔐 Support for various encoding techniques  
- 📂 Custom wordlist support  
- 🐞 Verbose and debug modes  
- 🌐 Proxy support (HTTP/S, SOCKS)  
- 💾 Session persistence  
- 🛡️ WAF evasion techniques  
- 📝 Report generation (HTML, JSON, TXT)  

---

## 🧰 Complete Installation (Global Access)

### ✅ Kali Linux / Debian-based Systems

1. Install dependencies and clone the repository:
   ```bash
   sudo apt update && sudo apt install -y git python3-pip
   git clone https://github.com/BCK570RM/lfi570rm.git
   cd lfi570rm
Install Python requirements:

pip3 install -r requirements.txt
Make the script executable and install globally:

 ```bash
chmod +x lfi570rm.py
sudo mv lfi570rm.py /usr/local/bin/lfi570rm
sudo mkdir -p /usr/local/share/lfi570rm
sudo cp -r wordlists /usr/local/share/lfi570rm/

Verify installation:

 ```bash
which lfi570rm
Now you can run the tool from anywhere:

 ```bash
lfi570rm -u "http://example.com/page.php?file=index.html"
🧹 Uninstallation
 ```bash
sudo rm /usr/local/bin/lfi570rm
sudo rm -rf /usr/local/share/lfi570rm
📦 Usage Examples
Basic scan:
 ```bash
lfi570rm -u "http://example.com/page.php?file=index.html"
With custom wordlist:
 ```bash
lfi570rm -u "http://example.com/page.php?file=index.html" -w /path/to/wordlist.txt
With 50 threads and proxy:
 ```bash
lfi570rm -u "http://example.com/page.php?file=index.html" -t 50 --proxy "http://127.0.0.1:8080"
🔄 Update the Tool
 ```bash
lfi570rm --update
📁 Notes
The tool will automatically use wordlists from:
 ```bash
/usr/local/share/lfi570rm/wordlists
To update wordlists manually:
 ```bash
sudo rm -rf /usr/local/share/lfi570rm/wordlists/*
sudo cp -r path/to/new/wordlists /usr/local/share/lfi570rm/
