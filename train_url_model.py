import os
import joblib
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from app.services.url_features import URLFeatureExtractor

def train_and_save_model_b():
    print("--- Training Model B (URL-Based Fallback) ---")
    data_path = os.path.join(os.path.dirname(__file__), "data", "dataset_2026_content.csv")
    model_path = os.path.join(os.path.dirname(__file__), "models", "url_model.joblib")
    
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}")
        return

    print("Loading Dataset...")
    df = pd.read_csv(data_path)
    df = df[['url', 'label']].dropna().drop_duplicates()
    
    print(f"Extracting URL features for {len(df)} rows. This takes a few seconds...")
    features_list = []
    
    for url in df['url']:
        features_list.append(URLFeatureExtractor.extract_features(url))
        
    X = np.array(features_list)
    y = df['label'].values
    
    print("Training Logistic Regression Model...")
    # Logistic Regression was our clear winner!
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X, y)
    
    # Quick Validation on the whole set (just to confirm it learned)
    preds = model.predict(X)
    acc = accuracy_score(y, preds)
    print(f"Model B trained successfully. Training Accuracy: {acc:.4f}")
    
    # Save the model
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f"Model B successfully saved to {model_path}")

if __name__ == "__main__":
    train_and_save_model_b()
