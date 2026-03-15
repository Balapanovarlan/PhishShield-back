import os
import joblib
from app.services.url_features import URLFeatureExtractor

class URLEngine:
    """Handles loading and predicting with Model B (URL-Based Fallback)."""
    
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "url_model.joblib")

    # XAI Dictionary mapping feature indices to human-readable names
    FEATURE_NAMES = [
        "URL total length",
        "Domain name length",
        "Number of dots in domain",
        "Number of hyphens in domain",
        "Presence of '@' symbol",
        "Double slash '//' in path",
        "Number of subdomains",
        "Use of IP address instead of domain",
        "Suspicious keywords (e.g., 'login', 'secure')",
        "High domain entropy (randomness)",
        "Count of special characters (?, =, &)"
    ]

    def __init__(self):
        self.model = None
        self.load_model()

    def load_model(self):
        """Loads Model B from disk."""
        if os.path.exists(self.MODEL_PATH):
            self.model = joblib.load(self.MODEL_PATH)
            print(f"URL Model (Model B) loaded from {self.MODEL_PATH}")
        else:
            print("URL Model file not found. Please train it first.")

    def get_explanations(self, features, is_phishing):
        """Generates XAI explanations using Logistic Regression coefficients."""
        if self.model is None or not hasattr(self.model, 'coef_'):
            return []

        # Get the weights for the features
        weights = self.model.coef_[0]
        
        # Calculate impact of each feature for this specific URL
        impacts = []
        for i in range(len(features)):
            # If the feature is present/active (> 0)
            if features[i] > 0:
                # The total impact is the feature value multiplied by its learned weight
                impact = features[i] * weights[i]
                impacts.append((impact, self.FEATURE_NAMES[i], features[i]))

        explanations = []
        if is_phishing:
            # Sort by highest positive impact (pushed the model towards Phishing)
            impacts.sort(key=lambda x: x[0], reverse=True)
            for imp, name, val in impacts[:3]: # Get top 3 reasons
                if imp > 0:
                    explanations.append(f"High Risk: Detected {name} (Value: {val:.2f})")
        else:
            # Sort by highest negative impact (pushed the model towards Legitimate)
            impacts.sort(key=lambda x: x[0])
            for imp, name, val in impacts[:3]:
                if imp < 0:
                    explanations.append(f"Safe Indicator: Normal {name}")

        if not explanations:
            explanations.append("Overall URL structure aligns with standard patterns.")
            
        return explanations

    def predict(self, url):
        """Extracts features from the URL string and predicts phishing status."""
        if self.model is None:
            return {"error": "URL Model not loaded"}

        try:
            features = URLFeatureExtractor.extract_features(url)
            
            # Predict
            prediction = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0][1] # Probability of phishing (label 1)
            
            is_phish = bool(prediction)
            
            # Generate XAI
            explanations = self.get_explanations(features, is_phish)
            
            return {
                "is_phishing": is_phish,
                "confidence": float(probability if prediction == 1 else 1 - probability),
                "risk_score": float(probability),
                "explanations": explanations
            }
        except Exception as e:
            return {"error": str(e)}
