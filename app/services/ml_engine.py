import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from app.services.ml_features import MLFeatureExtractor
from bs4 import BeautifulSoup
import requests
from app.core.i18n import translate

class MLEngine:
    """Handles ML model training, loading, and prediction."""
    
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "rf_model.joblib")
    NEW_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "dataset_2026_content.csv")
    OLD_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "phishing-website-detection-content-based")

    # Translation keys for features
    FEATURE_KEYS = [
        "feature_page_title", "feature_input_fields", "feature_buttons", "feature_images", "feature_submit_button", 
        "feature_external_links", "feature_password_field", "feature_email_input", "feature_hidden_elements", 
        "feature_audio_tags", "feature_video_tags", "feature_number_of_inputs", "feature_number_of_buttons", 
        "feature_number_of_images", "feature_number_of_options", "feature_number_of_lists", 
        "feature_table_headers", "feature_table_rows", "feature_hyperlinks", "feature_paragraphs", 
        "feature_scripts", "feature_title_length", "feature_h1_tags", "feature_h2_tags", "feature_h3_tags", 
        "feature_text_length", "feature_clickable_buttons", "feature_anchor_tags", "feature_image_tags", 
        "feature_div_elements", "feature_figures", "feature_footer", "feature_forms", "feature_text_areas", 
        "feature_iframes", "feature_text_inputs", "feature_meta_tags", "feature_navbars", "feature_object_tags", 
        "feature_picture_tags", "feature_source_tags", "feature_spans", "feature_tables"
    ]

    def __init__(self):
        self.model = None
        self.load_model()

    def load_model(self):
        """Loads the model from disk if it exists."""
        if os.path.exists(self.MODEL_PATH):
            self.model = joblib.load(self.MODEL_PATH)
            print(f"Model loaded from {self.MODEL_PATH}")
        else:
            print("Model file not found. Please train the model first.")

    def get_explanations(self, features, is_phishing, locale="en"):
        """Generates XAI explanations using Random Forest feature importances."""
        if self.model is None or not hasattr(self.model, 'feature_importances_'):
            return []

        importances = self.model.feature_importances_
        
        # Match features that are active (>0) with their model importance
        active_impacts = []
        for i in range(len(features)):
            if features[i] > 0:
                # In Random Forest, importance is always positive (0 to 1)
                active_impacts.append((importances[i], self.FEATURE_KEYS[i], features[i]))
                
        # Sort by most important
        active_impacts.sort(key=lambda x: x[0], reverse=True)
        
        explanations = []
        if is_phishing:
            for imp, key, val in active_impacts[:3]:
                name = translate(key, locale)
                explanations.append(translate("xai_high_risk", locale, name=name, val=val))
        else:
            for imp, key, val in active_impacts[:3]:
                name = translate(key, locale)
                explanations.append(translate("xai_safe_structure", locale, name=name))
                
        if not explanations:
             explanations.append(translate("xai_analysis_completed", locale))
             
        return explanations

    def train_model(self):
        """Trains a Random Forest model using the best available data."""
        print("Starting training process...")
        
        # 1. Try to use the NEW 2026 dataset first
        if os.path.exists(self.NEW_DATA_PATH):
            print(f"Using NEW 2026 dataset: {self.NEW_DATA_PATH}")
            df = pd.read_csv(self.NEW_DATA_PATH)
            # Remove URL and any duplicates
            df = df.drop('url', axis=1).drop_duplicates().sample(frac=1)
            X = df.drop('label', axis=1)
            y = df['label']
        
        # 2. Fallback to OLD 2022 dataset
        else:
            print("New dataset not found. Falling back to 2022 legacy data...")
            legit_path = os.path.join(self.OLD_DATA_DIR, "structured_data_legitimate.csv")
            phish_path = os.path.join(self.OLD_DATA_DIR, "structured_data_phishing.csv")
            
            if not os.path.exists(legit_path) or not os.path.exists(phish_path):
                print("Error: No training data found anywhere!")
                return

            legit_df = pd.read_csv(legit_path)
            phish_df = pd.read_csv(phish_path)
            df = pd.concat([legit_df, phish_df], axis=0).drop('URL', axis=1).drop_duplicates().sample(frac=1)
            X = df.drop('label', axis=1)
            y = df['label']
        
        # 3. Training
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Validate
        preds = self.model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        print(f"Model trained successfully. Accuracy: {acc:.4f}")
        
        # Save model
        os.makedirs(os.path.dirname(self.MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, self.MODEL_PATH)
        print(f"Model saved to {self.MODEL_PATH}")

    def predict(self, url, locale="en"):
        """Fetches URL content, extracts features, and predicts phishing status."""
        if self.model is None:
            return {"error": "Model not loaded"}

        try:
            # Add a timeout and generic user agent
            response = requests.get(url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code != 200:
                return {"error": f"Failed to fetch URL. Status code: {response.status_code}"}
            
            soup = BeautifulSoup(response.content, "html.parser")
            features = MLFeatureExtractor.extract_features(soup)
            
            # Reshape for prediction (1 row)
            prediction = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0][1] # Probability of being phishing (label 1)
            
            is_phish = bool(prediction)
            explanations = self.get_explanations(features, is_phish, locale)
            
            return {
                "is_phishing": is_phish,
                "confidence": float(probability if prediction == 1 else 1 - probability),
                "risk_score": float(probability),
                "explanations": explanations
            }
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    # Script to train the model manually
    engine = MLEngine()
    engine.train_model()
