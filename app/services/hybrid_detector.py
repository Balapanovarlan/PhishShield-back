import os
import pandas as pd
from app.services.ml_engine import MLEngine
from app.services.url_engine import URLEngine
from app.services.whois_checker import WhoisChecker
from app.core.i18n import translate
from urllib.parse import urlparse

class HybridDetector:
    """Combines White-lists, Black-lists, HTML analysis, URL analysis and WHOIS."""
    
    DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

    def __init__(self):
        self.ml_engine = MLEngine()
        self.url_engine = URLEngine()
        self.tranco_list = set()
        self.phishtank_list = set()
        self.majestic_list = set()
        self.load_lists()

    def load_lists(self):
        """Loads Tranco, PhishTank and Majestic CSVs into memory."""
        try:
            tranco_path = os.path.join(self.DATA_DIR, "tranco_latest.csv")
            if os.path.exists(tranco_path):
                df = pd.read_csv(tranco_path)
                self.tranco_list = set(str(u).lower().strip() for u in df['url'].tolist())
            
            phish_path = os.path.join(self.DATA_DIR, "phishtank_latest.csv")
            if os.path.exists(phish_path):
                df = pd.read_csv(phish_path)
                self.phishtank_list = set(str(u).lower().strip() for u in df['url'].tolist())
            
            majestic_path = os.path.join(self.DATA_DIR, "majestic_latest.csv")
            if os.path.exists(majestic_path):
                df = pd.read_csv(majestic_path)
                self.majestic_list = set(str(u).lower().strip() for u in df['Domain'].tolist())
                print(f"Loaded lists: Tranco, PhishTank, Majestic")
        except Exception as e:
            print(f"Error loading lists: {e}")

    def get_base_domain(self, domain):
        """Extracts base domain (e.g., www.youtube.com -> youtube.com)."""
        domain = domain.lower().strip()
        if domain.startswith("www."):
            return domain[4:]
        return domain

    def detect(self, url, locale="en"):
        """Main detection entry point with Extended Information."""
        url_clean = url.lower().strip()
        
        # 1. Black-list First
        if url_clean in self.phishtank_list:
            return {
                "status": "Phishing",
                "is_phishing": True,
                "confidence": 1.0,
                "risk_score": 1.0,
                "method": translate("method_phishtank", locale),
                "details": translate("details_phishtank", locale),
                "explanations": [translate("xai_url_high_risk", locale, name="Verified Phishing Database", val=1.0)],
                "breakdown": {
                    "html": 1.0, "url": 1.0, "reputation": 1.0, "protocol": 1.0
                }
            }

        # 2. Multi-Factor White-list
        parsed = urlparse(url)
        full_domain = (parsed.netloc or url.split('/')[0]).lower().strip()
        base_domain = self.get_base_domain(full_domain)
        
        in_tranco = full_domain in self.tranco_list or base_domain in self.tranco_list
        in_majestic = full_domain in self.majestic_list or base_domain in self.majestic_list
        age = WhoisChecker.get_domain_age(url)
        
        if (in_majestic or in_tranco) and (age >= 180 or age == -1):
            return {
                "status": "Legitimate",
                "is_phishing": False,
                "confidence": 1.0,
                "risk_score": 0.0,
                "method": translate("method_tranco", locale),
                "details": translate("details_tranco", locale),
                "explanations": [
                    translate("xai_domain_old", locale, val=age if age > 0 else "Unknown"),
                    translate("xai_url_safe_indicator", locale, name="Verified Domain Reputation")
                ],
                "breakdown": {
                    "html": 0.0, "url": 0.0, "reputation": 0.0, "protocol": 0.0
                }
            }

        # 3. Hybrid ML Analysis
        is_https = url.lower().startswith("https://")
        html_result = self.ml_engine.predict(url, locale)
        url_result = self.url_engine.predict(url, locale)

        html_risk = html_result.get("risk_score", 0.5) if "error" not in html_result else 0.5
        url_risk = url_result.get("risk_score", 0.5)
        
        # Reputation Score (Age-based)
        rep_risk = 0.0
        if 0 <= age < 14: rep_risk = 0.9
        elif 14 <= age < 90: rep_risk = 0.5
        elif age >= 365: rep_risk = 0.0
        else: rep_risk = 0.2 # Unknown or medium
        
        # Protocol Score
        protocol_risk = 0.0 if is_https else 0.8
        
        # Balanced Decision
        if "error" not in html_result:
            combined_risk = (html_risk * 0.6) + (url_risk * 0.25) + (rep_risk * 0.1) + (protocol_risk * 0.05)
            final_is_phishing = combined_risk > 0.6
        else:
            combined_risk = (url_risk * 0.7) + (rep_risk * 0.2) + (protocol_risk * 0.1)
            final_is_phishing = combined_risk > 0.5

        status = "Phishing" if final_is_phishing else "Legitimate"

        # Determine Detail Text
        if "error" in html_result:
            details = translate("details_model_b", locale, status=translate("status_phishing" if final_is_phishing else "status_legitimate", locale))
        else:
            if final_is_phishing:
                details = translate("details_model_a" if html_risk > 0.5 else "details_hybrid_phish", locale, status=translate("status_phishing", locale))
            else:
                details = translate("details_hybrid_safe", locale)

        # Build Explanations
        all_explanations = []
        if not is_https: all_explanations.append(translate("xai_no_https", locale))
        if 0 <= age < 30: all_explanations.append(translate("xai_domain_new", locale, val=age))
        elif age >= 365: all_explanations.append(translate("xai_domain_old", locale, val=age))
            
        if final_is_phishing:
            if html_risk > 0.5 and "error" not in html_result: all_explanations.extend(html_result["explanations"])
            if url_risk > 0.5: all_explanations.extend(url_result["explanations"])
        else:
            if "error" not in html_result: all_explanations.extend(html_result["explanations"][:2])
            all_explanations.extend(url_result["explanations"][:2])
            
        if not all_explanations:
            all_explanations.append(translate("xai_analysis_completed", locale))

        return {
            "status": status,
            "is_phishing": final_is_phishing,
            "confidence": max(html_result.get("confidence", 0.0) if "error" not in html_result else 0.0, url_result.get("confidence", 0.0)),
            "risk_score": min(1.0, combined_risk),
            "method": translate("method_hybrid", locale),
            "details": details,
            "explanations": all_explanations[:4],
            "breakdown": {
                "html": float(html_risk),
                "url": float(url_risk),
                "reputation": float(rep_risk),
                "protocol": float(protocol_risk)
            }
        }
