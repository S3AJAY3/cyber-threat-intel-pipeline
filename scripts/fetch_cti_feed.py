import requests
import os
import csv
from io import StringIO
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv('OTX_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
MALSHARE_API_KEY = os.getenv('MALSHARE_API_KEY')

def fetch_otx_feed():
    print("\n--- OTX API Feed ---")
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"  # fallback if you have an API key
        if not OTX_API_KEY:
            # Use public feed instead
            url = "https://otx.alienvault.com/api/v1/pulses/?limit=5"

        headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            for pulse in data.get('results', []):
                print(f"Pulse Name: {pulse.get('name')}")
                print(f"Created: {pulse.get('created')}")
                print(f"Author: {pulse.get('author_name')}")
                print(f"Description: {pulse.get('description')}\n")
        else:
            print(f"Error fetching OTX API: {response.status_code} - {response.text}")
    except Exception as e:
        print("Exception fetching OTX feed:", e)

def fetch_malshare_api():
    print("\n--- Malshare API Feed ---")
    if not MALSHARE_API_KEY:
        print("No Malshare API key set in environment.")
        return

    url = 'https://malshare.com/api.php'
    params = {
        'api_key': MALSHARE_API_KEY,
        'action': 'getlist'
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if not data:
                print("No data received from Malshare.")
                return
            # Show only first 5 samples
            for sample in data[:5]:
                print(f"SHA256: {sample.get('sha256', 'N/A')} | First Seen: {sample.get('first_seen', 'N/A')}")
        else:
            print(f"Error fetching Malshare API: {response.status_code} - {response.text}")
    except Exception as e:
        print("Exception fetching Malshare API:", e)

def fetch_abuseipdb():
    print("\n--- AbuseIPDB Feed ---")
    if not ABUSEIPDB_API_KEY:
        print("No AbuseIPDB API key set in environment.")
        return

    try:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {"confidenceMinimum": 90}

        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for ip in data.get('data', [])[:5]:
                print(f"IP: {ip.get('ipAddress')} | Reports: {ip.get('totalReports')} | Confidence: {ip.get('abuseConfidenceScore')}")
        elif response.status_code == 429:
            print("Rate limit reached for AbuseIPDB. Try again tomorrow or upgrade your plan.")
        else:
            print(f"Error fetching AbuseIPDB: {response.status_code} - {response.text}")
    except Exception as e:
        print("Exception fetching AbuseIPDB:", e)

def fetch_urlhaus_csv():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    print("\n--- URLHaus CSV Feed ---")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            csv_data = StringIO(response.text)
            reader = csv.reader(csv_data)
            count = 0
            for row in reader:
                if row and not row[0].startswith("#"):
                    try:
                        print(f"URL: {row[2]}")
                        count += 1
                        if count == 5:
                            break
                    except IndexError:
                        continue
        else:
            print(f"Error fetching URLHaus CSV: {response.status_code}")
    except Exception as e:
        print("Exception fetching URLHaus CSV:", e)

if __name__ == "__main__":
    fetch_otx_feed()
    fetch_malshare_api()
    fetch_abuseipdb()
    fetch_urlhaus_csv()
