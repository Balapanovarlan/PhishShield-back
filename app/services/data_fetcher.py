import os
import requests
import gzip
import zipfile
import pandas as pd
from io import BytesIO
from datetime import datetime

class DataFetcher:
    """Handles data downloads for PhishTank and Tranco."""
    
    PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv.gz"
    TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
    DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

    def __init__(self):
        if not os.path.exists(self.DATA_DIR):
            os.makedirs(self.DATA_DIR)

    def fetch_phishtank(self):
        """Downloads and extracts the latest phishing data from PhishTank."""
        print(f"[{datetime.now()}] Fetching PhishTank data...")
        headers = {'User-Agent': 'phishshield/diploma-project'}
        response = requests.get(self.PHISHTANK_URL, headers=headers)
        
        if response.status_code == 200:
            content = gzip.decompress(response.content)
            df = pd.read_csv(BytesIO(content))
            save_path = os.path.join(self.DATA_DIR, "phishtank_latest.csv")
            df.to_csv(save_path, index=False)
            print(f"Success: PhishTank data saved to {save_path}")
            return df
        else:
            print(f"Error: PhishTank download failed (Status: {response.status_code})")
            return None

    def fetch_tranco(self):
        """Downloads and extracts the latest Tranco top-1m list."""
        print(f"[{datetime.now()}] Fetching Tranco top-1m list...")
        response = requests.get(self.TRANCO_URL)
        
        if response.status_code == 200:
            with zipfile.ZipFile(BytesIO(response.content)) as z:
                # Tranco zip usually contains one csv file
                csv_filename = z.namelist()[0]
                with z.open(csv_filename) as f:
                    # Tranco CSV doesn't have headers, first col is rank, second is domain
                    df = pd.read_csv(f, names=['rank', 'url'])
                    save_path = os.path.join(self.DATA_DIR, "tranco_latest.csv")
                    df.to_csv(save_path, index=False)
                    print(f"Success: Tranco data saved to {save_path}")
                    return df
        else:
            print(f"Error: Tranco download failed (Status: {response.status_code})")
            return None

if __name__ == "__main__":
    fetcher = DataFetcher()
    fetcher.fetch_phishtank()
    fetcher.fetch_tranco()
