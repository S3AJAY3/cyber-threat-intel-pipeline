import requests
import os
import csv
import json
from io import StringIO
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv('OTX_API_KEY')
MALSHARE_API_KEY = os.getenv('MALSHARE_API_KEY')

def fetch_otx_feed():
    print("\n--- OTX API Feed ---")
    results = []
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        if not OTX_API_KEY:
            url = "https://otx.alienvault.com/api/v1/pulses/?limit=100"

        headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            # Handle pagination if needed (example below)
            pulses = data.get('results', [])
            results.extend(pulses)

            # Simple pagination example if 'next' URL provided:
            next_url = data.get('next')
            while next_url:
                response = requests.get(next_url, headers=headers, timeout=10)
                if response.status_code != 200:
                    break
                data = response.json()
                pulses = data.get('results', [])
                results.extend(pulses)
                next_url = data.get('next')

            for pulse in results:
                print(f"Pulse Name: {pulse.get('name')}")
        else:
            print(f"Error fetching OTX API: {response.status_code} - {response.text}")
    except Exception as e:
        print("Exception fetching OTX feed:", e)
    return results

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
            for sample in data:
                print(f"SHA256: {sample.get('sha256', 'N/A')} | First Seen: {sample.get('first_seen', 'N/A')}")
                results.append(sample)
        else:
            print(f"Error fetching Malshare API: {response.status_code} - {response.text}")
    except Exception as e:
        print("Exception fetching Malshare API:", e)
    return results

def fetch_urlhaus_csv():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    print("\n--- URLHaus CSV Feed ---")
    results = []
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            csv_data = StringIO(response.text)
            reader = csv.reader(csv_data)
            for row in reader:
                if row and not row[0].startswith("#"):
                    try:
                        print(f"URL: {row[2]}")
                        results.append({"url": row[2]})
                    except IndexError:
                        continue
        else:
            print(f"Error fetching URLHaus CSV: {response.status_code}")
    except Exception as e:
        print("Exception fetching URLHaus CSV:", e)
    return results

if __name__ == "__main__":
    all_data = {
        "otx": fetch_otx_feed(),
        "malshare": fetch_malshare_api(),
        "urlhaus": fetch_urlhaus_csv()
    }

    with open("../cti_data.json", "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2)

    print("\n✅ Saved all CTI data to cti_data.json")
