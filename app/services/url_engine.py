import os
import joblib
from app.services.url_features import URLFeatureExtractor
from app.core.i18n import translate

class URLEngine:
    """Handles loading and predicting with Model B (URL-Based Fallback)."""
    
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "url_model.joblib")

    # Translation keys for URL features
    FEATURE_KEYS = [
        "url_feature_total_length",
        "url_feature_domain_length",
        "url_feature_dots",
        "url_feature_hyphens",
        "url_feature_at",
        "url_feature_double_slash",
        "url_feature_subdomains",
        "url_feature_ip",
        "url_feature_keywords",
        "url_feature_entropy",
        "url_feature_special_chars"
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

    def get_explanations(self, features, is_phishing, locale="en"):
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
                impacts.append((impact, self.FEATURE_KEYS[i], features[i]))

        explanations = []
        if is_phishing:
            # Sort by highest positive impact (pushed the model towards Phishing)
            impacts.sort(key=lambda x: x[0], reverse=True)
            for imp, key, val in impacts[:3]: # Get top 3 reasons
                if imp > 0:
                    name = translate(key, locale)
                    explanations.append(translate("xai_url_high_risk", locale, name=name, val=val))
        else:
            # Sort by highest negative impact (pushed the model towards Legitimate)
            impacts.sort(key=lambda x: x[0])
            for imp, key, val in impacts[:3]:
                if imp < 0:
                    name = translate(key, locale)
                    explanations.append(translate("xai_url_safe_indicator", locale, name=name))

        if not explanations:
            explanations.append(translate("xai_url_standard_patterns", locale))
            
        return explanations

    def predict(self, url, locale="en"):
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
            explanations = self.get_explanations(features, is_phish, locale)
            
            return {
                "is_phishing": is_phish,
                "confidence": float(probability if prediction == 1 else 1 - probability),
                "risk_score": float(probability),
                "explanations": explanations
            }
        except Exception as e:
            return {"error": str(e)}
