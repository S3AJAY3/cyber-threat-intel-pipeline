import requests
import os
import csv
import json
from io import StringIO
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv('OTX_API_KEY')
MALSHARE_API_KEY = os.getenv('MALSHARE_API_KEY')
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")

def fetch_otx_feed():
    print("\n--- OTX API Feed ---")
    results = []
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed" if OTX_API_KEY else "https://otx.alienvault.com/api/v1/pulses/?limit=50"
        headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            pulses = data.get('results', [])
            results.extend(pulses)

            next_url = data.get('next')
            while next_url and len(results) < 50:
                response = requests.get(next_url, headers=headers, timeout=10)
                if response.status_code != 200:
                    break
                data = response.json()
                pulses = data.get('results', [])
                results.extend(pulses)
                next_url = data.get('next')

            for pulse in results[:50]:
                print(f"Pulse Name: {pulse.get('name')}")
        else:
            print(f"Error fetching OTX API: {response.status_code} - {response.text}")
    except Exception as e:
        print("Exception fetching OTX feed:", e)
    return results[:50]

def fetch_malshare_api():
    print("\n--- Malshare API Feed ---")
    results = []
    if not MALSHARE_API_KEY:
        print("No Malshare API key set in environment.")
        return results

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
                return results
            for sample in data[:50]:
                print(f"SHA256: {sample.get('sha256', 'N/A')} | First Seen: {sample.get('first_seen', 'N/A')}")
                results.append(sample)
        else:
            print(f"Error fetching Malshare API: {response.status_code} - {response.text}")
    except Exception as e:
        print("Exception fetching Malshare API:", e)
    return results

def fetch_urlhaus_csv():
    print("\n--- URLHaus CSV Feed ---")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    results = []
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            csv_data = StringIO(response.text)
            reader = csv.reader(csv_data)
            count = 0
            for row in reader:
                if count >= 50:
                    break
                if row and not row[0].startswith("#"):
                    try:
                        print(f"URL: {row[2]}")
                        results.append({"url": row[2]})
                        count += 1
                    except IndexError:
                        continue
        else:
            print(f"Error fetching URLHaus CSV: {response.status_code}")
    except Exception as e:
        print("Exception fetching URLHaus CSV:", e)
    return results

def fetch_threatfox():
    print("\n--- Threatfox ---")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Auth-Key": THREATFOX_API_KEY
    }
    payload = {"query": "get_iocs", "limit": 50}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok":
            print("❌ Invalid query_status:", data)
            return []

        iocs = data.get("data", [])[:50]  # Enforce limit
        for ioc in iocs:
            print(f"IOC: {ioc.get('ioc', 'N/A')} | Type: {ioc.get('ioc_type', 'N/A')}")
        return iocs
    except Exception as e:
        print(f"❌ Error fetching ThreatFox data: {e}")
        return []

if __name__ == "__main__":
    all_data = {
        "otx": fetch_otx_feed(),
        "malshare": fetch_malshare_api(),
        "urlhaus": fetch_urlhaus_csv(),
        "threatfox": fetch_threatfox()
    }

    with open("../cti_data.json", "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2)

    print("\n✅ Saved all CTI data to cti_data.json")
