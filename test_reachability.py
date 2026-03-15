import pandas as pd
import requests
import random
import warnings
warnings.filterwarnings("ignore")

def test_reachability(n=20):
    df = pd.read_csv("data/phishtank_latest.csv")
    urls = df['url'].tolist()
    random_urls = random.sample(urls, n)
    
    reachable = 0
    timeout_or_error = 0
    
    print(f"Testing reachability of {n} random PhishTank URLs...")
    for url in random_urls:
        try:
            r = requests.get(url, timeout=3, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                reachable += 1
                print(f"[LIVE] {url}")
            else:
                timeout_or_error += 1
                print(f"[DEAD] {url} (Status: {r.status_code})")
        except:
            timeout_or_error += 1
            print(f"[DEAD] {url} (Connection Error/Timeout)")
            
    print(f"\n--- Reachability Summary ---")
    print(f"Total Tested: {n}")
    print(f"Reachable (200 OK): {reachable} ({(reachable/n)*100:.1f}%)")
    print(f"Offline/Dead: {timeout_or_error} ({(timeout_or_error/n)*100:.1f}%)")

if __name__ == "__main__":
    test_reachability()
