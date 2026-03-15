import os
import pandas as pd
from urllib.parse import urlparse
from app.services.ml_engine import MLEngine
from app.services.url_engine import URLEngine

class HybridDetector:
    """Combines list lookups, HTML-based ML (Model A), and URL-based ML (Model B)."""
    
    DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

    def __init__(self):
        self.phishtank_set = set()
        self.tranco_set = set()
        self.ml_engine = MLEngine()      # Model A (Deep Scan / Content)
        self.url_engine = URLEngine()    # Model B (Fallback / URL)
        self.load_lists()

    def load_lists(self):
        """Loads PhishTank and Tranco CSVs into memory for fast lookup."""
        try:
            pt_path = os.path.join(self.DATA_DIR, "phishtank_latest.csv")
            if os.path.exists(pt_path):
                pt_df = pd.read_csv(pt_path)
                self.phishtank_set = set(pt_df['url'].apply(self.normalize_url))
                print(f"Loaded {len(self.phishtank_set)} phishing URLs.")

            tr_path = os.path.join(self.DATA_DIR, "tranco_latest.csv")
            if os.path.exists(tr_path):
                tr_df = pd.read_csv(tr_path)
                self.tranco_set = set(tr_df['url'].apply(self.normalize_url))
                print(f"Loaded {len(self.tranco_set)} legitimate domains.")
        except Exception as e:
            print(f"Error loading lists: {e}")

    def normalize_url(self, url):
        """Standardizes URL for consistent lookup."""
        try:
            if not isinstance(url, str):
                return ""
            parsed = urlparse(url)
            netloc = parsed.netloc or parsed.path
            return netloc.lower().replace("www.", "")
        except:
            return str(url).lower()

    def detect(self, url):
        """Executes the Diploma-Optimized Hybrid Detection Flow."""
        norm_url = self.normalize_url(url)
        
        # ---------------------------------------------------------
        # STEP 1: DETERMINISTIC LIST LOOKUP (100% Confidence)
        # ---------------------------------------------------------
        if norm_url in self.tranco_set:
            return {
                "status": "Legitimate",
                "method": "Tranco White-list (100% Match)",
                "risk_score": 0.0,
                "confidence": 1.0,
                "details": "URL found in Tranco Top-1M safe list. No ML scan required."
            }
        
        if norm_url in self.phishtank_set:
            return {
                "status": "Phishing",
                "method": "PhishTank Black-list (100% Match)",
                "risk_score": 1.0,
                "confidence": 1.0,
                "details": "URL found in PhishTank verified phishing database. Threat confirmed."
            }
        
        # ---------------------------------------------------------
        # STEP 2: MODEL A - DEEP SCAN (Content Analysis)
        # ---------------------------------------------------------
        print(f"URL {url} not in lists. Attempting Deep Scan (Model A)...")
        ml_result = self.ml_engine.predict(url)
        
        if "error" not in ml_result:
            status = "Phishing" if ml_result["is_phishing"] else "Legitimate"
            return {
                "status": status,
                "method": "Model A: Deep Scan (HTML Content Analysis)",
                "risk_score": ml_result["risk_score"],
                "confidence": ml_result["confidence"],
                "details": f"Site is REACHABLE. Model A predicted '{status}' based on HTML structures."
            }

        # ---------------------------------------------------------
        # STEP 3: MODEL B - FALLBACK SCAN (URL Analysis)
        # ---------------------------------------------------------
        print(f"Site unreachable ({ml_result.get('error')}). Falling back to URL Scan (Model B)...")
        url_result = self.url_engine.predict(url)
        
        if "error" in url_result:
            return {
                "status": "Unknown",
                "method": "Error",
                "risk_score": 0.5,
                "confidence": 0.0,
                "error": url_result["error"]
            }

        status = "Phishing" if url_result["is_phishing"] else "Legitimate"
        return {
            "status": status,
            "method": "Model B: Fallback Scan (URL Topography Analysis)",
            "risk_score": url_result["risk_score"],
            "confidence": url_result["confidence"],
            "details": f"Site is NOT REACHABLE. Model B predicted '{status}' based on URL string patterns (Logistic Regression)."
        }
