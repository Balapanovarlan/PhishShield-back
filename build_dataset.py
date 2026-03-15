import os
import pandas as pd
import requests
from bs4 import BeautifulSoup
from app.services.ml_features import MLFeatureExtractor
from tqdm import tqdm
import concurrent.futures
import warnings
warnings.filterwarnings("ignore")

class DatasetBuilder:
    """Automates the creation of a new 2026 Phishing Dataset."""
    
    DATA_DIR = "data"
    OUTPUT_FILE = "data/dataset_2026_content.csv"

    def __init__(self, legit_count=6000, phish_count=4000):
        self.legit_count = legit_count
        self.phish_count = phish_count
        self.extractor = MLFeatureExtractor()
        self.headers = {'User-Agent': 'PhishShield-Bot/1.0 (Diploma Project)'}

    def prepare_urls(self):
        """Loads and samples URLs from Tranco and PhishTank."""
        print("Loading URL sources...")
        tranco_df = pd.read_csv(os.path.join(self.DATA_DIR, "tranco_latest.csv"))
        phishtank_df = pd.read_csv(os.path.join(self.DATA_DIR, "phishtank_latest.csv"))

        # Format Tranco to full URLs (they are domains)
        legit_urls = ["http://" + url for url in tranco_df['url'].head(self.legit_count).tolist()]
        phish_urls = phishtank_df['url'].head(self.phish_count).tolist()

        return legit_urls, phish_urls

    def fetch_and_extract(self, url, label):
        """Worker function to visit a site and extract its features."""
        try:
            response = requests.get(url, timeout=5, verify=False, headers=self.headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, "html.parser")
                features = self.extractor.extract_features(soup)
                return features + [label, url]
        except:
            pass
        return None

    def build(self, max_workers=20):
        """Main loop with multi-threading for speed."""
        legit_urls, phish_urls = self.prepare_urls()
        all_tasks = [(url, 0) for url in legit_urls] + [(url, 1) for url in phish_urls]
        
        results = []
        print(f"Starting crawl for {len(all_tasks)} sites using {max_workers} threads...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self.fetch_and_extract, url, label): url for url, label in all_tasks}
            
            for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(all_tasks)):
                res = future.result()
                if res:
                    results.append(res)

        # Save to CSV
        columns = [f"f{i}" for i in range(43)] + ["label", "url"]
        df = pd.DataFrame(results, columns=columns)
        df.to_csv(self.OUTPUT_FILE, index=False)
        print(f"\nSuccess! New dataset saved to {self.OUTPUT_FILE}")
        print(f"Total reachable sites captured: {len(df)}")

if __name__ == "__main__":
    # FULL DATASET BUILD: 60,000 Legitimate and 40,000 Phishing
    # This will take several hours depending on your internet speed.
    builder = DatasetBuilder(legit_count=60000, phish_count=40000)
    builder.build(max_workers=50) 
