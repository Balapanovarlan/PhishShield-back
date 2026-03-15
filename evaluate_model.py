import os
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

def evaluate_efficiency():
    # Paths
    model_path = os.path.join(os.path.dirname(__file__), "models", "rf_model.joblib")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "phishing-website-detection-content-based")
    
    if not os.path.exists(model_path):
        print("Model not found. Please train it first.")
        return

    # Load Model
    model = joblib.load(model_path)
    
    # Load Data (using the same split logic as training for consistency)
    legit_df = pd.read_csv(os.path.join(data_dir, "structured_data_legitimate.csv"))
    phish_df = pd.read_csv(os.path.join(data_dir, "structured_data_phishing.csv"))
    df = pd.concat([legit_df, phish_df], axis=0).drop('URL', axis=1).drop_duplicates()
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Since we used random_state=42 in training, we can reconstruct the test set
    from sklearn.model_selection import train_test_split
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("--- PhishShield ML Efficiency Report ---")
    predictions = model.predict(X_test)
    
    # 1. Basic Metrics
    acc = accuracy_score(y_test, predictions)
    print(f"Overall Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=['Legitimate', 'Phishing']))
    
    # 2. Confusion Matrix
    cm = confusion_matrix(y_test, predictions)
    print("\nConfusion Matrix:")
    print(cm)
    
    # Note: For your diploma, you can save this as an image
    # plt.figure(figsize=(8,6))
    # sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    # plt.title('Confusion Matrix - PhishShield')
    # plt.ylabel('Actual')
    # plt.xlabel('Predicted')
    # plt.savefig('efficiency_report.png')

if __name__ == "__main__":
    evaluate_efficiency()
