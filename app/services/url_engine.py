import os
import joblib
from app.services.url_features import URLFeatureExtractor

class URLEngine:
    """Handles loading and predicting with Model B (URL-Based Fallback)."""
    
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "url_model.joblib")

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

    def predict(self, url):
        """Extracts features from the URL string and predicts phishing status."""
        if self.model is None:
            return {"error": "URL Model not loaded"}

        try:
            features = URLFeatureExtractor.extract_features(url)
            
            # Predict
            prediction = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0][1] # Probability of phishing (label 1)
            
            return {
                "is_phishing": bool(prediction),
                "confidence": float(probability if prediction == 1 else 1 - probability),
                "risk_score": float(probability)
            }
        except Exception as e:
            return {"error": str(e)}
