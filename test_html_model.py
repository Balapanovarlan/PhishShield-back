import os
import sys
import pandas as pd
import requests
import random
from bs4 import BeautifulSoup
import warnings

# Add backend directory to path so we can import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.ml_engine import MLEngine

# Suppress SSL warnings
warnings.filterwarnings("ignore")

def test_on_live_data(n_per_class=30):
    print("--- Testing HTML-based PhishShield Model on Live Data ---")
    engine = MLEngine()
    
    # 1. Load Phishing URLs (PhishTank)
    phish_df = pd.read_csv("data/phishtank_latest.csv")
    phish_urls = phish_df['url'].tolist()
    random.shuffle(phish_urls)
    
    # 2. Load Legitimate URLs (Tranco)
    legit_df = pd.read_csv("data/tranco_latest.csv")
    legit_urls = ["https://" + url for url in legit_df['url'].tolist()] # Add https://
    random.shuffle(legit_urls)
    
    results = []
    
    def process_urls(url_list, expected_label, class_name):
        found = 0
        tried = 0
        print(f"\nSearching for {n_per_class} live {class_name} URLs...")
        
        for url in url_list:
            if found >= n_per_class:
                break
            tried += 1
            if tried > 100: # Don't search forever
                break
                
            try:
                # Try to fetch
                r = requests.get(url, timeout=3, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code == 200:
                    print(f"[LIVE] {url}")
                    # Predict using the engine
                    prediction = engine.predict(url)
                    
                    if "error" not in prediction:
                        is_phish = prediction["is_phishing"]
                        correct = (is_phish == expected_label)
                        
                        results.append({
                            "url": url,
                            "actual": class_name,
                            "predicted": "Phishing" if is_phish else "Legitimate",
                            "correct": correct,
                            "confidence": prediction["confidence"]
                        })
                        
                        status = "✅ CORRECT" if correct else "❌ WRONG"
                        print(f"      Result: {status} (Confidence: {prediction['confidence']:.2f})")
                        found += 1
                else:
                    pass # Just skip dead ones
            except Exception:
                pass # Just skip errors
    
    # Process both classes
    process_urls(phish_urls, True, "Phishing")
    process_urls(legit_urls, False, "Legitimate")
    
    # Summary
    if not results:
        print("\nNo live URLs found to test.")
        return
        
    df_results = pd.DataFrame(results)
    accuracy = (df_results['correct'].sum() / len(df_results)) * 100
    
    print("\n--- Final Summary ---")
    print(df_results[['actual', 'predicted', 'correct', 'confidence']])
    print(f"\nOverall Accuracy on Live Data: {accuracy:.1f}%")
    
    # Save results for future reference
    df_results.to_csv("data/test_results_live.csv", index=False)
    print(f"Detailed results saved to backend/data/test_results_live.csv")

if __name__ == "__main__":
    test_on_live_data()
