import os
import pandas as pd
import requests
import concurrent.futures
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

def check_reachability(url):
    """Checks if a URL is live."""
    try:
        r = requests.get(url, timeout=4, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            return url
    except:
        pass
    return None

def create_test_set(target_count=50):
    print("Loading untrained PhishTank data...")
    # Load PhishTank data
    pt_df = pd.read_csv("data/phishtank_latest.csv")
    
    # Skip the first 40,000 rows (used in training attempt)
    untrained_urls = pt_df['url'].iloc[40000:].tolist()
    print(f"Found {len(untrained_urls)} unseen phishing URLs.")
    
    live_urls = []
    print(f"Scanning for {target_count} reachable sites...")
    
    # Use ThreadPool to scan fast
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # Submit tasks in batches to avoid overwhelming the system
        future_to_url = {executor.submit(check_reachability, url): url for url in untrained_urls[:1000]}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_url), total=1000):
            result = future.result()
            if result:
                live_urls.append(result)
                if len(live_urls) >= target_count:
                    # Cancel remaining futures if we hit our target early
                    for f in future_to_url:
                        f.cancel()
                    break

    if live_urls:
        df = pd.DataFrame({'url': live_urls[:target_count], 'label': 1})
        output_path = "data/test_live_phishing.csv"
        df.to_csv(output_path, index=False)
        print(f"\nSuccess! Saved {len(live_urls[:target_count])} live, untrained phishing URLs to {output_path}")
    else:
        print("\nCould not find any live URLs in this batch.")

if __name__ == "__main__":
    # Let's find 50 guaranteed live, unseen phishing sites
    create_test_set(target_count=50)
