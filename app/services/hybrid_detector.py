import os
import pandas as pd
from urllib.parse import urlparse
from app.services.ml_engine import MLEngine

class HybridDetector:
    """Combines list lookups (PhishTank/Tranco) with ML detection."""
    
    DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

    def __init__(self):
        self.phishtank_set = set()
        self.tranco_set = set()
        self.ml_engine = MLEngine()
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
        """Hybrid detection logic."""
        norm_url = self.normalize_url(url)
        
        # 1. Check Tranco (Safe List)
        if norm_url in self.tranco_set:
            return {
                "status": "Legitimate",
                "method": "Tranco White-list",
                "risk_score": 0.0,
                "confidence": 1.0,
                "details": "URL found in Tranco Top-1M list."
            }
        
        # 2. Check PhishTank (Black List)
        if norm_url in self.phishtank_set:
            return {
                "status": "Phishing",
                "method": "PhishTank Black-list",
                "risk_score": 1.0,
                "confidence": 1.0,
                "details": "URL found in PhishTank verified phishing database."
            }
        
        # 3. Fallback to ML Detection
        print(f"URL {url} not in lists. Running ML Engine...")
        ml_result = self.ml_engine.predict(url)
        
        if "error" in ml_result:
            return {
                "status": "Unknown",
                "method": "ML Engine Error",
                "risk_score": 0.5,
                "confidence": 0.0,
                "error": ml_result["error"]
            }

        status = "Phishing" if ml_result["is_phishing"] else "Legitimate"
        
        return {
            "status": status,
            "method": "Machine Learning (Content Analysis)",
            "risk_score": ml_result["risk_score"],
            "confidence": ml_result["confidence"],
            "details": f"ML model predicted '{status}' based on HTML content analysis."
        }
